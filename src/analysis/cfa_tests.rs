// use std::fs::File;
//
// use anyhow::Result;
// use serde::{de::Error, Deserialize, Deserializer};
//
// use super::*;
// use crate::{
//     analysis::cfa::AnalyzerState,
//     obj::{ObjArchitecture, ObjInfo, ObjKind, ObjSection, ObjSectionKind},
// };
//
// fn bytestr_to_bytes<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
// where D: Deserializer<'de> {
//     let hex_str = String::deserialize(deserializer)?;
//
//     if hex_str.len() % 2 != 0 {
//         return Err(D::Error::custom("hex string must have even length"));
//     }
//
//     let bytes = (0..hex_str.len())
//         .step_by(2)
//         .map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16))
//         .collect::<Result<Vec<u8>, _>>()
//         .map_err(D::Error::custom)?;
//
//     Ok(bytes)
// }
//
// fn get_fn_start<'de, D>(deserializer: D) -> Result<u32, D::Error>
// where D: Deserializer<'de> {
//     let hex_str = String::deserialize(deserializer)?;
//     if hex_str.len() != 8 {
//         return Err(D::Error::custom(format!("expected 8 hex chars, got {}", hex_str.len())));
//     }
//     let start = u32::from_str_radix(&*hex_str, 16).map_err(D::Error::custom)?;
//     Ok(start)
// }
//
// #[derive(Debug, Deserialize)]
// struct TestConfig {
//     test_id: u32,
//     #[serde(deserialize_with = "get_fn_start")]
//     function_start: u32,
//     #[serde(deserialize_with = "bytestr_to_bytes")]
//     function_bytes: Vec<u8>,
//     #[serde(deserialize_with = "get_fn_start")]
//     jump_table_start: u32,
//     #[serde(deserialize_with = "bytestr_to_bytes")]
//     jump_table_bytes: Vec<u8>,
// }
//
// // helper func to create an ObjInfo
// fn make_code_section(base_addr: u32, instructions: &[u8]) -> ObjSection {
//     ObjSection {
//         name: ".text".into(),
//         kind: ObjSectionKind::Code,
//         address: base_addr as u64,
//         size: instructions.len() as u64,
//         data: Vec::from(instructions),
//         align: 0x10000,
//         ..Default::default()
//     }
// }
//
// fn make_data_section(base_addr: u32, instructions: &[u8]) -> ObjSection {
//     ObjSection {
//         name: ".rdata".into(),
//         kind: ObjSectionKind::ReadOnlyData,
//         address: base_addr as u64,
//         size: instructions.len() as u64,
//         data: Vec::from(instructions),
//         align: 0x10000,
//         ..Default::default()
//     }
// }
//
// fn create_dummy_obj(code_section: ObjSection, rdata_section: Option<ObjSection>) -> ObjInfo {
//     let mut sections: Vec<ObjSection> = vec![];
//     if let Some(rdata_section) = rdata_section {
//         sections.push(rdata_section);
//     }
//     sections.push(code_section);
//     ObjInfo::new(ObjKind::Executable, ObjArchitecture::PowerPc, "test.exe".into(), vec![], sections)
// }
//
// #[test]
// fn test_super_basic_cfa() -> Result<()> {
//     let test_cfg: Vec<TestConfig> =
//         serde_yaml::from_reader(File::open("assets/tests/cfa_tests.yml")?)?;
//     let cur_test = &test_cfg[0];
//     assert_eq!(cur_test.test_id, 0);
//     let obj = create_dummy_obj(
//         make_code_section(cur_test.function_start, &cur_test.function_bytes),
//         None,
//     );
//     let mut state = AnalyzerState::default();
//     let start_addr = SectionAddress::new(0, cur_test.function_start);
//     // CFA completed with no errors
//     let res = state.process_function_at(&obj, start_addr).unwrap_or_else(|e| panic!("{:?}", e));
//     // we have one more function
//     assert!(res);
//     assert_eq!(state.functions.len(), 1);
//     let func = state.functions.get(&start_addr);
//     assert!(func.is_some());
//     let func = func.unwrap();
//     assert!(func.is_function());
//     // does the detected function end match our expected end?
//     assert_eq!(func.end, Some(start_addr + cur_test.function_bytes.len() as u32));
//     // assert that we have slices
//     assert!(func.slices.is_some());
//     let slices = func.slices.as_ref().unwrap();
//     // this func should only have 1 basic block
//     assert_eq!(slices.blocks.len(), 1);
//     Ok(())
// }
//
// // Absolute general skeleton:
// // lis r12, <jump_table_addr-hi>
// // addi r12, r12, <jump_table_addr-lo>
// // rlwinm r0, rX, 0x2, 0x0, 0x1d // NOTE: rX likely has the table bounds, but because it's absolute, and because there are funny stack memes, we can ignore it
// // lwzx r0, r12, r0
// // mtctr r0
// // bctr
// // <jump_table_addr>
//
// // Relative bytes (no rlwinm) general skeleton:
// // cmplwi crN, rX, <limit>
// // bgt crN, default
// // lis r12, <jump_table_addr-hi>
// // addi r12, r12, <jump_table_addr-lo>
// // lbzx r0, r12, rX
// // slwi r0, r0, 0x2
// // lis r12, <start_of_the_cases-hi>
// // nop
// // addi r12, r12, <start_of_the_cases-lo>
// // add r12, r12, r0
// // mtctr r12
// // bctr
// // <start_of_the_cases>
// // ...
// // <default>
//
// // Relative bytes (no rlwinm) alternate general skeleton:
// // cmplwi crN, rX, <limit>
// // bgt crN, default
// // lis r12, <jump_table_addr-hi>
// // addi r12, r12, <jump_table_addr-lo>
// // lbzx r0, r12, rX
// // lis r12, <start_of_the_cases-hi>
// // addi r12, r12, <start_of_the_cases-lo>
// // add r12, r12, r0
// // mtctr r12
// // nop
// // nop
// // bctr
// // <start_of_the_cases>
// // ...
// // <default>
//
// // DDR Universe: FUN_822671c0
//
// // Relative bytes (rlwinm after lbzx) general skeleton
// // (remember, the entries in the jump table need to be multiplied by 4):
// // cmplwi crN, rX, <limit>
// // bgt crN, default
// // lis r12, <jump_table_addr-hi>
// // addi r12, r12, <jump_table_addr-lo>
// // lbzx r0, r12, rX
// // rlwinm r0, r0, 0x2, 0x0, 0x1d
// // lis r12, <start_of_the_cases-hi>
// // nop
// // addi r12, r12, <start_of_the_cases-lo>
// // add r12, r12, r0
// // mtctr r12
// // bctr
// // <start_of_the_cases>
// // ...
// // <default>
//
// // TBRB: FUN_823349f8
// // halo 3: FUN_82588e08
//
// // Relative shorts (no rlwinm)
// // for the life of me i can't find one
//
// // Relative shorts (rlwinm before lhzx) general skeleton
// // (remember, the entries in the jump table need to be multiplied by 2): // UPDATE: uhhh i guess maybe you don't need to multiply by 2 after all?
// // cmplwi crN, rX, <limit>
// // bgt crN, default
// // lis r12, <jump_table_addr-hi>
// // addi r12, r12, <jump_table_addr-lo>
// // rlwinm r0, rX, 0x1, 0x0, 0x1e
// // lhzx r0, r12, r0
// // lis r12, <start_of_the_cases-hi>
// // addi r12, r12, <start_of_the_cases-lo>
// // add r12, r12, r0
// // mtctr r12
// // nop
// // bctr
// // <start_of_the_cases>
// // ...
// // <default>
//
// #[test]
// fn test_jump_table_absolute_1() -> Result<()> {
//     let test_cfg: Vec<TestConfig> =
//         serde_yaml::from_reader(File::open("assets/tests/cfa_tests.yml")?)?;
//     let cur_test = &test_cfg[1];
//     assert_eq!(cur_test.test_id, 1);
//     let obj = create_dummy_obj(
//         make_code_section(cur_test.function_start, &cur_test.function_bytes),
//         None,
//     );
//     let mut state = AnalyzerState::default();
//     let start_addr = SectionAddress::new(0, cur_test.function_start);
//     // CFA completed with no errors
//     let res = state.process_function_at(&obj, start_addr).unwrap_or_else(|e| panic!("{:?}", e));
//     // we have one more function
//     assert!(res);
//     assert_eq!(state.functions.len(), 1);
//     let func = state.functions.get(&start_addr);
//     assert!(func.is_some());
//     let func = func.unwrap();
//     assert!(func.is_function());
//     // does the detected function end match our expected end?
//     assert_eq!(func.end, Some(start_addr + cur_test.function_bytes.len() as u32));
//     // for this func, we should have 1 jump table
//     assert_eq!(state.jump_tables.is_empty(), false);
//     assert_eq!(state.jump_tables.len(), 1);
//     // and there should be 4 entries in it
//     let jump_table_entry = state.jump_tables.get(&SectionAddress::new(0, 0x820869fc));
//     assert!(jump_table_entry.is_some());
//     // 4 entries * 4 bytes per entry
//     assert_eq!(*jump_table_entry.unwrap(), 4 * 4);
//     // we should also have a lotta basic blocks
//     assert!(func.slices.is_some());
//     let slices = func.slices.as_ref().unwrap();
//     assert!(slices.blocks.len() > 5); // idk the exact number but i know it's more than 5
//     Ok(())
// }
//
// #[test]
// fn test_jump_table_absolute_2() -> Result<()> {
//     let test_cfg: Vec<TestConfig> =
//         serde_yaml::from_reader(File::open("assets/tests/cfa_tests.yml")?)?;
//     let cur_test = &test_cfg[2];
//     assert_eq!(cur_test.test_id, 2);
//     let obj = create_dummy_obj(
//         make_code_section(cur_test.function_start, &cur_test.function_bytes),
//         None,
//     );
//     let mut state = AnalyzerState::default();
//     let start_addr = SectionAddress::new(0, cur_test.function_start);
//     // CFA completed with no errors
//     let res = state.process_function_at(&obj, start_addr).unwrap_or_else(|e| panic!("{:?}", e));
//     // we have one more function
//     assert!(res);
//     assert_eq!(state.functions.len(), 1);
//     let func = state.functions.get(&start_addr);
//     assert!(func.is_some());
//     let func = func.unwrap();
//     assert!(func.is_function());
//     // does the detected function end match our expected end?
//     assert_eq!(func.end, Some(start_addr + cur_test.function_bytes.len() as u32));
//     // for this func, we should have 1 jump table
//     assert_eq!(state.jump_tables.is_empty(), false);
//     assert_eq!(state.jump_tables.len(), 1);
//     // and there should be 4 entries in it
//     let jump_table_entry = state.jump_tables.get(&SectionAddress::new(0, 0x827f9434));
//     assert!(jump_table_entry.is_some());
//     // 4 entries * 4 bytes per entry
//     assert_eq!(*jump_table_entry.unwrap(), 4 * 4);
//     // we should also have a lotta basic blocks
//     assert!(func.slices.is_some());
//     let slices = func.slices.as_ref().unwrap();
//     assert!(slices.blocks.len() > 5); // idk the exact number but i know it's more than 5
//     Ok(())
// }
//
// // this one's also got VMX! for added fun
// #[test]
// fn test_jump_table_absolute_3() -> Result<()> {
//     let test_cfg: Vec<TestConfig> =
//         serde_yaml::from_reader(File::open("assets/tests/cfa_tests.yml")?)?;
//     let cur_test = &test_cfg[3];
//     assert_eq!(cur_test.test_id, 3);
//     let obj = create_dummy_obj(
//         make_code_section(cur_test.function_start, &cur_test.function_bytes),
//         None,
//     );
//     let mut state = AnalyzerState::default();
//     let start_addr = SectionAddress::new(0, cur_test.function_start);
//     // CFA completed with no errors
//     let res = state.process_function_at(&obj, start_addr).unwrap_or_else(|e| panic!("{:?}", e));
//     // we have one more function
//     assert!(res);
//     assert_eq!(state.functions.len(), 1);
//     let func = state.functions.get(&start_addr);
//     assert!(func.is_some());
//     let func = func.unwrap();
//     assert!(func.is_function());
//     // does the detected function end match our expected end?
//     assert_eq!(func.end, Some(start_addr + cur_test.function_bytes.len() as u32));
//     // for this func, we should have 1 jump table
//     assert_eq!(state.jump_tables.is_empty(), false);
//     assert_eq!(state.jump_tables.len(), 1);
//     // and there should be 4 entries in it
//     let jump_table_entry = state.jump_tables.get(&SectionAddress::new(0, 0x82fbb464));
//     assert!(jump_table_entry.is_some());
//     // 4 entries * 4 bytes per entry
//     assert_eq!(*jump_table_entry.unwrap(), 4 * 4);
//     // we should also have a lotta basic blocks
//     assert!(func.slices.is_some());
//     let slices = func.slices.as_ref().unwrap();
//     assert!(slices.blocks.len() > 5); // idk the exact number but i know it's more than 5
//     Ok(())
// }
//
// #[test]
// fn test_jump_table_relative_bytes_1() -> Result<()> {
//     let test_cfg: Vec<TestConfig> =
//         serde_yaml::from_reader(File::open("assets/tests/cfa_tests.yml")?)?;
//     let cur_test = &test_cfg[4];
//     assert_eq!(cur_test.test_id, 4);
//     let obj = create_dummy_obj(
//         make_code_section(cur_test.function_start, &cur_test.function_bytes),
//         Some(make_data_section(cur_test.jump_table_start, &cur_test.jump_table_bytes)),
//     );
//     let mut state = AnalyzerState::default();
//     // section 1 is .text now that we have a relative jump table in .rdata
//     let start_addr = SectionAddress::new(1, cur_test.function_start);
//     // CFA completed with no errors
//     let res = state.process_function_at(&obj, start_addr).unwrap_or_else(|e| panic!("{:?}", e));
//     // we have one more function
//     assert!(res);
//     assert_eq!(state.functions.len(), 1);
//     let func = state.functions.get(&start_addr);
//     assert!(func.is_some());
//     let func = func.unwrap();
//     assert!(func.is_function());
//     // does the detected function end match our expected end?
//     assert_eq!(func.end, Some(start_addr + cur_test.function_bytes.len() as u32));
//     // for this func, we should have 1 jump table
//     assert_eq!(state.jump_tables.is_empty(), false);
//     assert_eq!(state.jump_tables.len(), 1);
//     let jump_table_entry =
//         state.jump_tables.get(&SectionAddress::new(0, cur_test.jump_table_start));
//     assert!(jump_table_entry.is_some());
//     assert_eq!(*jump_table_entry.unwrap(), 105);
//     // TODO: verify basic block count
//     Ok(())
// }
//
// #[test]
// fn test_jump_table_relative_bytes_2() -> Result<()> {
//     let test_cfg: Vec<TestConfig> =
//         serde_yaml::from_reader(File::open("assets/tests/cfa_tests.yml")?)?;
//     let cur_test = &test_cfg[5];
//     assert_eq!(cur_test.test_id, 5);
//     let obj = create_dummy_obj(
//         make_code_section(cur_test.function_start, &cur_test.function_bytes),
//         Some(make_data_section(cur_test.jump_table_start, &cur_test.jump_table_bytes)),
//     );
//     let mut state = AnalyzerState::default();
//     // section 1 is .text now that we have a relative jump table in .rdata
//     let start_addr = SectionAddress::new(1, cur_test.function_start);
//     // CFA completed with no errors
//     let res = state.process_function_at(&obj, start_addr).unwrap_or_else(|e| panic!("{:?}", e));
//     // we have one more function
//     assert!(res);
//     assert_eq!(state.functions.len(), 1);
//     let func = state.functions.get(&start_addr);
//     assert!(func.is_some());
//     let func = func.unwrap();
//     assert!(func.is_function());
//     // does the detected function end match our expected end?
//     assert_eq!(func.end, Some(start_addr + cur_test.function_bytes.len() as u32));
//     // for this func, we should have 1 jump table
//     assert_eq!(state.jump_tables.is_empty(), false);
//     assert_eq!(state.jump_tables.len(), 1);
//     let jump_table_entry =
//         state.jump_tables.get(&SectionAddress::new(0, cur_test.jump_table_start));
//     assert!(jump_table_entry.is_some());
//     assert_eq!(*jump_table_entry.unwrap(), 0x1c);
//     // TODO: verify basic block count
//     Ok(())
// }
//
// #[test]
// fn test_jump_table_relative_bytes_3() -> Result<()> {
//     let test_cfg: Vec<TestConfig> =
//         serde_yaml::from_reader(File::open("assets/tests/cfa_tests.yml")?)?;
//     let cur_test = &test_cfg[6];
//     assert_eq!(cur_test.test_id, 6);
//     let obj = create_dummy_obj(
//         make_code_section(cur_test.function_start, &cur_test.function_bytes),
//         Some(make_data_section(cur_test.jump_table_start, &cur_test.jump_table_bytes)),
//     );
//     let mut state = AnalyzerState::default();
//     // section 1 is .text now that we have a relative jump table in .rdata
//     let start_addr = SectionAddress::new(1, cur_test.function_start);
//     // CFA completed with no errors
//     let res = state.process_function_at(&obj, start_addr).unwrap_or_else(|e| panic!("{:?}", e));
//     // we have one more function
//     assert!(res);
//     assert_eq!(state.functions.len(), 1);
//     let func = state.functions.get(&start_addr);
//     assert!(func.is_some());
//     let func = func.unwrap();
//     assert!(func.is_function());
//     // does the detected function end match our expected end?
//     assert_eq!(func.end, Some(start_addr + cur_test.function_bytes.len() as u32));
//     // for this func, we should have 1 jump table
//     assert_eq!(state.jump_tables.is_empty(), false);
//     assert_eq!(state.jump_tables.len(), 1);
//     let jump_table_entry =
//         state.jump_tables.get(&SectionAddress::new(0, cur_test.jump_table_start));
//     assert!(jump_table_entry.is_some());
//     assert_eq!(*jump_table_entry.unwrap(), 11);
//     // TODO: verify basic block count
//     Ok(())
// }
//
// #[test]
// fn test_jump_table_relative_bytes_4() -> Result<()> {
//     let test_cfg: Vec<TestConfig> =
//         serde_yaml::from_reader(File::open("assets/tests/cfa_tests.yml")?)?;
//     let cur_test = &test_cfg[7];
//     assert_eq!(cur_test.test_id, 7);
//     let obj = create_dummy_obj(
//         make_code_section(cur_test.function_start, &cur_test.function_bytes),
//         Some(make_data_section(cur_test.jump_table_start, &cur_test.jump_table_bytes)),
//     );
//     let mut state = AnalyzerState::default();
//     // section 1 is .text now that we have a relative jump table in .rdata
//     let start_addr = SectionAddress::new(1, cur_test.function_start);
//     // CFA completed with no errors
//     let res = state.process_function_at(&obj, start_addr).unwrap_or_else(|e| panic!("{:?}", e));
//     // we have one more function
//     assert!(res);
//     assert_eq!(state.functions.len(), 1);
//     let func = state.functions.get(&start_addr);
//     assert!(func.is_some());
//     let func = func.unwrap();
//     assert!(func.is_function());
//     // does the detected function end match our expected end?
//     assert_eq!(func.end, Some(start_addr + cur_test.function_bytes.len() as u32));
//     // for this func, we should have 1 jump table
//     assert_eq!(state.jump_tables.is_empty(), false);
//     assert_eq!(state.jump_tables.len(), 1);
//     let jump_table_entry =
//         state.jump_tables.get(&SectionAddress::new(0, cur_test.jump_table_start));
//     assert!(jump_table_entry.is_some());
//     assert_eq!(*jump_table_entry.unwrap(), 12);
//     // TODO: verify basic block count
//     Ok(())
// }
//
// #[test]
// fn test_jump_table_relative_bytes_5() -> Result<()> {
//     let test_cfg: Vec<TestConfig> =
//         serde_yaml::from_reader(File::open("assets/tests/cfa_tests.yml")?)?;
//     let cur_test = &test_cfg[8];
//     assert_eq!(cur_test.test_id, 8);
//     let obj = create_dummy_obj(
//         make_code_section(cur_test.function_start, &cur_test.function_bytes),
//         Some(make_data_section(cur_test.jump_table_start, &cur_test.jump_table_bytes)),
//     );
//     let mut state = AnalyzerState::default();
//     // section 1 is .text now that we have a relative jump table in .rdata
//     let start_addr = SectionAddress::new(1, cur_test.function_start);
//     // CFA completed with no errors
//     let res = state.process_function_at(&obj, start_addr).unwrap_or_else(|e| panic!("{:?}", e));
//     // we have one more function
//     assert!(res);
//     assert_eq!(state.functions.len(), 1);
//     let func = state.functions.get(&start_addr);
//     assert!(func.is_some());
//     let func = func.unwrap();
//     assert!(func.is_function());
//     // does the detected function end match our expected end?
//     assert_eq!(func.end, Some(start_addr + cur_test.function_bytes.len() as u32));
//     // for this func, we should have 1 jump table
//     assert_eq!(state.jump_tables.is_empty(), false);
//     assert_eq!(state.jump_tables.len(), 1);
//     // TODO: verify number of jump table entries and basic block count
//     let jump_table_entry =
//         state.jump_tables.get(&SectionAddress::new(0, cur_test.jump_table_start));
//     assert!(jump_table_entry.is_some());
//     assert_eq!(*jump_table_entry.unwrap(), 12);
//     // TODO: verify basic block count
//     Ok(())
// }
//
// #[test]
// fn test_jump_table_relative_bytes_6() -> Result<()> {
//     let test_cfg: Vec<TestConfig> =
//         serde_yaml::from_reader(File::open("assets/tests/cfa_tests.yml")?)?;
//     let cur_test = &test_cfg[9];
//     assert_eq!(cur_test.test_id, 9);
//     let obj = create_dummy_obj(
//         make_code_section(cur_test.function_start, &cur_test.function_bytes),
//         Some(make_data_section(cur_test.jump_table_start, &cur_test.jump_table_bytes)),
//     );
//     let mut state = AnalyzerState::default();
//     // section 1 is .text now that we have a relative jump table in .rdata
//     let start_addr = SectionAddress::new(1, cur_test.function_start);
//     // CFA completed with no errors
//     let res = state.process_function_at(&obj, start_addr).unwrap_or_else(|e| panic!("{:?}", e));
//     // we have one more function
//     assert!(res);
//     assert_eq!(state.functions.len(), 1);
//     let func = state.functions.get(&start_addr);
//     assert!(func.is_some());
//     let func = func.unwrap();
//     assert!(func.is_function());
//     // does the detected function end match our expected end?
//     assert_eq!(func.end, Some(start_addr + cur_test.function_bytes.len() as u32));
//     // for this func, we should have 1 jump table
//     assert_eq!(state.jump_tables.is_empty(), false);
//     assert_eq!(state.jump_tables.len(), 1);
//     let jump_table_entry =
//         state.jump_tables.get(&SectionAddress::new(0, cur_test.jump_table_start));
//     assert!(jump_table_entry.is_some());
//     assert_eq!(*jump_table_entry.unwrap(), 10);
//     // TODO: verify basic block count
//     Ok(())
// }
//
// #[test]
// fn test_jump_table_relative_bytes_7() -> Result<()> {
//     let test_cfg: Vec<TestConfig> =
//         serde_yaml::from_reader(File::open("assets/tests/cfa_tests.yml")?)?;
//     let cur_test = &test_cfg[10];
//     assert_eq!(cur_test.test_id, 10);
//     let obj = create_dummy_obj(
//         make_code_section(cur_test.function_start, &cur_test.function_bytes),
//         Some(make_data_section(cur_test.jump_table_start, &cur_test.jump_table_bytes)),
//     );
//     let mut state = AnalyzerState::default();
//     // section 1 is .text now that we have a relative jump table in .rdata
//     let start_addr = SectionAddress::new(1, cur_test.function_start);
//     // CFA completed with no errors
//     let res = state.process_function_at(&obj, start_addr).unwrap_or_else(|e| panic!("{:?}", e));
//     // we have one more function
//     assert!(res);
//     assert_eq!(state.functions.len(), 1);
//     let func = state.functions.get(&start_addr);
//     assert!(func.is_some());
//     let func = func.unwrap();
//     assert!(func.is_function());
//     // does the detected function end match our expected end?
//     assert_eq!(func.end, Some(start_addr + cur_test.function_bytes.len() as u32));
//     // for this func, we should have 1 jump table
//     assert_eq!(state.jump_tables.is_empty(), false);
//     assert_eq!(state.jump_tables.len(), 1);
//     let jump_table_entry =
//         state.jump_tables.get(&SectionAddress::new(0, cur_test.jump_table_start));
//     assert!(jump_table_entry.is_some());
//     assert_eq!(*jump_table_entry.unwrap(), 0x15);
//     // TODO: verify basic block count
//     Ok(())
// }
//
// #[test]
// fn test_jump_table_relative_shorts_1() -> Result<()> {
//     let test_cfg: Vec<TestConfig> =
//         serde_yaml::from_reader(File::open("assets/tests/cfa_tests.yml")?)?;
//     let cur_test = &test_cfg[11];
//     assert_eq!(cur_test.test_id, 11);
//     let obj = create_dummy_obj(
//         make_code_section(cur_test.function_start, &cur_test.function_bytes),
//         Some(make_data_section(cur_test.jump_table_start, &cur_test.jump_table_bytes)),
//     );
//     let mut state = AnalyzerState::default();
//     // section 1 is .text now that we have a relative jump table in .rdata
//     let start_addr = SectionAddress::new(1, cur_test.function_start);
//     // CFA completed with no errors
//     let res = state.process_function_at(&obj, start_addr).unwrap_or_else(|e| panic!("{:?}", e));
//     // we have one more function
//     assert!(res);
//     assert_eq!(state.functions.len(), 1);
//     let func = state.functions.get(&start_addr);
//     assert!(func.is_some());
//     let func = func.unwrap();
//     assert!(func.is_function());
//     // does the detected function end match our expected end?
//     assert_eq!(func.end, Some(start_addr + cur_test.function_bytes.len() as u32));
//     // for this func, we should have 1 jump table
//     assert_eq!(state.jump_tables.is_empty(), false);
//     assert_eq!(state.jump_tables.len(), 1);
//     let jump_table_entry =
//         state.jump_tables.get(&SectionAddress::new(0, cur_test.jump_table_start));
//     assert!(jump_table_entry.is_some());
//     assert_eq!(*jump_table_entry.unwrap(), 14 * 2);
//     // TODO: verify basic block count
//     Ok(())
// }
//
// #[test]
// fn test_jump_table_relative_shorts_2() -> Result<()> {
//     let test_cfg: Vec<TestConfig> =
//         serde_yaml::from_reader(File::open("assets/tests/cfa_tests.yml")?)?;
//     let cur_test = &test_cfg[12];
//     assert_eq!(cur_test.test_id, 12);
//     let obj = create_dummy_obj(
//         make_code_section(cur_test.function_start, &cur_test.function_bytes),
//         Some(make_data_section(cur_test.jump_table_start, &cur_test.jump_table_bytes)),
//     );
//     let mut state = AnalyzerState::default();
//     // section 1 is .text now that we have a relative jump table in .rdata
//     let start_addr = SectionAddress::new(1, cur_test.function_start);
//     // CFA completed with no errors
//     let res = state.process_function_at(&obj, start_addr).unwrap_or_else(|e| panic!("{:?}", e));
//     // we have one more function
//     assert!(res);
//     assert_eq!(state.functions.len(), 1);
//     let func = state.functions.get(&start_addr);
//     assert!(func.is_some());
//     let func = func.unwrap();
//     assert!(func.is_function());
//     // does the detected function end match our expected end?
//     assert_eq!(func.end, Some(start_addr + cur_test.function_bytes.len() as u32));
//     // for this func, we should have 1 jump table
//     assert_eq!(state.jump_tables.is_empty(), false);
//     assert_eq!(state.jump_tables.len(), 1);
//     let jump_table_entry =
//         state.jump_tables.get(&SectionAddress::new(0, cur_test.jump_table_start));
//     assert!(jump_table_entry.is_some());
//     assert_eq!(*jump_table_entry.unwrap(), 47 * 2);
//     // TODO: verify basic block count
//     Ok(())
// }
//
// #[test]
// fn test_jump_table_relative_shorts_3() -> Result<()> {
//     let test_cfg: Vec<TestConfig> =
//         serde_yaml::from_reader(File::open("assets/tests/cfa_tests.yml")?)?;
//     let cur_test = &test_cfg[13];
//     assert_eq!(cur_test.test_id, 13);
//     let obj = create_dummy_obj(
//         make_code_section(cur_test.function_start, &cur_test.function_bytes),
//         Some(make_data_section(cur_test.jump_table_start, &cur_test.jump_table_bytes)),
//     );
//     let mut state = AnalyzerState::default();
//     // section 1 is .text now that we have a relative jump table in .rdata
//     let start_addr = SectionAddress::new(1, cur_test.function_start);
//     // CFA completed with no errors
//     let res = state.process_function_at(&obj, start_addr).unwrap_or_else(|e| panic!("{:?}", e));
//     // we have one more function
//     assert!(res);
//     assert_eq!(state.functions.len(), 1);
//     let func = state.functions.get(&start_addr);
//     assert!(func.is_some());
//     let func = func.unwrap();
//     assert!(func.is_function());
//     // does the detected function end match our expected end?
//     assert_eq!(func.end, Some(start_addr + cur_test.function_bytes.len() as u32));
//     // for this func, we should have 1 jump table
//     assert_eq!(state.jump_tables.is_empty(), false);
//     assert_eq!(state.jump_tables.len(), 1);
//     let jump_table_entry =
//         state.jump_tables.get(&SectionAddress::new(0, cur_test.jump_table_start));
//     assert!(jump_table_entry.is_some());
//     assert_eq!(*jump_table_entry.unwrap(), 64 * 2);
//     // TODO: verify basic block count
//     Ok(())
// }
//
// #[test]
// fn test_jump_table_relative_shorts_4() -> Result<()> {
//     let test_cfg: Vec<TestConfig> =
//         serde_yaml::from_reader(File::open("assets/tests/cfa_tests.yml")?)?;
//     let cur_test = &test_cfg[14];
//     assert_eq!(cur_test.test_id, 14);
//     let obj = create_dummy_obj(
//         make_code_section(cur_test.function_start, &cur_test.function_bytes),
//         Some(make_data_section(cur_test.jump_table_start, &cur_test.jump_table_bytes)),
//     );
//     let mut state = AnalyzerState::default();
//     // section 1 is .text now that we have a relative jump table in .rdata
//     let start_addr = SectionAddress::new(1, cur_test.function_start);
//     // CFA completed with no errors
//     let res = state.process_function_at(&obj, start_addr).unwrap_or_else(|e| panic!("{:?}", e));
//     // we have one more function
//     assert!(res);
//     assert_eq!(state.functions.len(), 1);
//     let func = state.functions.get(&start_addr);
//     assert!(func.is_some());
//     let func = func.unwrap();
//     assert!(func.is_function());
//     // does the detected function end match our expected end?
//     assert_eq!(func.end, Some(start_addr + cur_test.function_bytes.len() as u32));
//     // for this func, we should have 1 jump table
//     assert_eq!(state.jump_tables.is_empty(), false);
//     assert_eq!(state.jump_tables.len(), 1);
//     let jump_table_entry =
//         state.jump_tables.get(&SectionAddress::new(0, cur_test.jump_table_start));
//     assert!(jump_table_entry.is_some());
//     assert_eq!(*jump_table_entry.unwrap(), 8 * 2);
//     // TODO: verify basic block count
//     Ok(())
// }
//
// #[test]
// fn test_jump_table_relative_shorts_5() -> Result<()> {
//     let test_cfg: Vec<TestConfig> =
//         serde_yaml::from_reader(File::open("assets/tests/cfa_tests.yml")?)?;
//     let cur_test = &test_cfg[15];
//     assert_eq!(cur_test.test_id, 15);
//     let obj = create_dummy_obj(
//         make_code_section(cur_test.function_start, &cur_test.function_bytes),
//         Some(make_data_section(cur_test.jump_table_start, &cur_test.jump_table_bytes)),
//     );
//     let mut state = AnalyzerState::default();
//     // section 1 is .text now that we have a relative jump table in .rdata
//     let start_addr = SectionAddress::new(1, cur_test.function_start);
//     // CFA completed with no errors
//     let res = state.process_function_at(&obj, start_addr).unwrap_or_else(|e| panic!("{:?}", e));
//     // we have one more function
//     assert!(res);
//     assert_eq!(state.functions.len(), 1);
//     let func = state.functions.get(&start_addr);
//     assert!(func.is_some());
//     let func = func.unwrap();
//     assert!(func.is_function());
//     // does the detected function end match our expected end?
//     assert_eq!(func.end, Some(start_addr + cur_test.function_bytes.len() as u32));
//     // for this func, we should have 1 jump table
//     assert_eq!(state.jump_tables.is_empty(), false);
//     assert_eq!(state.jump_tables.len(), 1);
//     let jump_table_entry =
//         state.jump_tables.get(&SectionAddress::new(0, cur_test.jump_table_start));
//     assert!(jump_table_entry.is_some());
//     assert_eq!(*jump_table_entry.unwrap(), 10 * 2);
//     // TODO: verify basic block count
//     Ok(())
// }
//
// #[test]
// fn test_jump_table_relative_shorts_6() -> Result<()> {
//     let test_cfg: Vec<TestConfig> =
//         serde_yaml::from_reader(File::open("assets/tests/cfa_tests.yml")?)?;
//     let cur_test = &test_cfg[16];
//     assert_eq!(cur_test.test_id, 16);
//     let obj = create_dummy_obj(
//         make_code_section(cur_test.function_start, &cur_test.function_bytes),
//         Some(make_data_section(cur_test.jump_table_start, &cur_test.jump_table_bytes)),
//     );
//     let mut state = AnalyzerState::default();
//     // section 1 is .text now that we have a relative jump table in .rdata
//     let start_addr = SectionAddress::new(1, cur_test.function_start);
//     // CFA completed with no errors
//     let res = state.process_function_at(&obj, start_addr).unwrap_or_else(|e| panic!("{:?}", e));
//     // we have one more function
//     assert!(res);
//     assert_eq!(state.functions.len(), 1);
//     let func = state.functions.get(&start_addr);
//     assert!(func.is_some());
//     let func = func.unwrap();
//     assert!(func.is_function());
//     // does the detected function end match our expected end?
//     assert_eq!(func.end, Some(start_addr + cur_test.function_bytes.len() as u32));
//     // for this func, we should have 1 jump table
//     assert_eq!(state.jump_tables.is_empty(), false);
//     assert_eq!(state.jump_tables.len(), 1);
//     let jump_table_entry =
//         state.jump_tables.get(&SectionAddress::new(0, cur_test.jump_table_start));
//     assert!(jump_table_entry.is_some());
//     assert_eq!(*jump_table_entry.unwrap(), 28 * 2);
//     // TODO: verify basic block count
//     Ok(())
// }
//
// #[test]
// fn test_jump_table_relative_shorts_7() -> Result<()> {
//     let test_cfg: Vec<TestConfig> =
//         serde_yaml::from_reader(File::open("assets/tests/cfa_tests.yml")?)?;
//     let cur_test = &test_cfg[17];
//     assert_eq!(cur_test.test_id, 17);
//     let obj = create_dummy_obj(
//         make_code_section(cur_test.function_start, &cur_test.function_bytes),
//         Some(make_data_section(cur_test.jump_table_start, &cur_test.jump_table_bytes)),
//     );
//     let mut state = AnalyzerState::default();
//     // section 1 is .text now that we have a relative jump table in .rdata
//     let start_addr = SectionAddress::new(1, cur_test.function_start);
//     // CFA completed with no errors
//     let res = state.process_function_at(&obj, start_addr).unwrap_or_else(|e| panic!("{:?}", e));
//     // we have one more function
//     assert!(res);
//     assert_eq!(state.functions.len(), 1);
//     let func = state.functions.get(&start_addr);
//     assert!(func.is_some());
//     let func = func.unwrap();
//     assert!(func.is_function());
//     // does the detected function end match our expected end?
//     assert_eq!(func.end, Some(start_addr + cur_test.function_bytes.len() as u32));
//     // for this func, we should have 1 jump table
//     assert_eq!(state.jump_tables.is_empty(), false);
//     assert_eq!(state.jump_tables.len(), 1);
//     let jump_table_entry =
//         state.jump_tables.get(&SectionAddress::new(0, cur_test.jump_table_start));
//     assert!(jump_table_entry.is_some());
//     assert_eq!(*jump_table_entry.unwrap(), 30 * 2);
//     // TODO: verify basic block count
//     Ok(())
// }
//
// #[test]
// fn test_jump_table_relative_shorts_8() -> Result<()> {
//     let test_cfg: Vec<TestConfig> =
//         serde_yaml::from_reader(File::open("assets/tests/cfa_tests.yml")?)?;
//     let cur_test = &test_cfg[18];
//     assert_eq!(cur_test.test_id, 18);
//     let obj = create_dummy_obj(
//         make_code_section(cur_test.function_start, &cur_test.function_bytes),
//         Some(make_data_section(cur_test.jump_table_start, &cur_test.jump_table_bytes)),
//     );
//     let mut state = AnalyzerState::default();
//     // section 1 is .text now that we have a relative jump table in .rdata
//     let start_addr = SectionAddress::new(1, cur_test.function_start);
//     // CFA completed with no errors
//     let res = state.process_function_at(&obj, start_addr).unwrap_or_else(|e| panic!("{:?}", e));
//     // we have one more function
//     assert!(res);
//     assert_eq!(state.functions.len(), 1);
//     let func = state.functions.get(&start_addr);
//     assert!(func.is_some());
//     let func = func.unwrap();
//     assert!(func.is_function());
//     // does the detected function end match our expected end?
//     assert_eq!(func.end, Some(start_addr + cur_test.function_bytes.len() as u32));
//     // for this func, we should have 1 jump table
//     assert_eq!(state.jump_tables.is_empty(), false);
//     assert_eq!(state.jump_tables.len(), 1);
//     let jump_table_entry =
//         state.jump_tables.get(&SectionAddress::new(0, cur_test.jump_table_start));
//     assert!(jump_table_entry.is_some());
//     assert_eq!(*jump_table_entry.unwrap(), 10 * 2);
//     // TODO: verify basic block count
//     Ok(())
// }
//
// // this one has an absolute jump table,
// // except different registers are used when rlwinm'ing - it stores R4 to 0x50(R1), and then loads from 0x50(R1) into R3, and R3 is then used to index.
// // to get this to pass, we need some sort of mechanism that keeps track of what's in the stack at any given time
// // or: since this is an absolute jump table, and i haven't seen this for any relative jump tables,
// // we can ignore the indexing and just iterate through the jump table normally (keep going until you find not-an-address)
// #[test]
// #[ignore]
// fn test_jump_table_absolute_stack_meme() -> Result<()> {
//     let test_cfg: Vec<TestConfig> =
//         serde_yaml::from_reader(File::open("assets/tests/cfa_tests.yml")?)?;
//     let cur_test = &test_cfg[19];
//     assert_eq!(cur_test.test_id, 19);
//     let obj = create_dummy_obj(
//         make_code_section(cur_test.function_start, &cur_test.function_bytes),
//         None,
//     );
//     let mut state = AnalyzerState::default();
//     let start_addr = SectionAddress::new(0, cur_test.function_start);
//     // CFA completed with no errors
//     let res = state.process_function_at(&obj, start_addr).unwrap_or_else(|e| panic!("{:?}", e));
//     // we have one more function
//     assert!(res);
//     assert_eq!(state.functions.len(), 1);
//     // NOTE: this func ends prematurely at a b it suspects is a tail call
//     // because of this, we have to run finalize_functions...but even so, it's claiming the end of the function is at the end of the block
//     // and not the actual end. furthermore, it doesn't seem to find a jump table...not sure what's going on in the context of this test.
//     // This works in the real thing because this func is in pdata, so there's a known end.
//     state.finalize_functions(&obj, true)?;
//     let func = state.functions.get(&start_addr);
//     assert!(func.is_some());
//     let func = func.unwrap();
//     assert!(func.is_function());
//     // does the detected function end match our expected end?
//     assert_eq!(func.end, Some(start_addr + cur_test.function_bytes.len() as u32));
//     // for this func, we should have 1 jump table
//     assert_eq!(state.jump_tables.is_empty(), false);
//     assert_eq!(state.jump_tables.len(), 1);
//     // and there should be 4 entries in it
//     let jump_table_entry = state.jump_tables.get(&SectionAddress::new(0, 0x82185be8));
//     assert!(jump_table_entry.is_some());
//     // 0x169 entries * 4 bytes per entry
//     assert_eq!(*jump_table_entry.unwrap(), 0x169 * 4);
//     // we should also have a lotta basic blocks
//     assert!(func.slices.is_some());
//     let slices = func.slices.as_ref().unwrap();
//     assert!(slices.blocks.len() > 5); // idk the exact number but i know it's more than 5
//     Ok(())
// }
//
// // Fails because of premature b that it thinks is a tail call.
// #[test]
// #[ignore]
// fn test_jump_table_relative_bytes_with_rlwinm_1() -> Result<()> {
//     let test_cfg: Vec<TestConfig> =
//         serde_yaml::from_reader(File::open("assets/tests/cfa_tests.yml")?)?;
//     let cur_test = &test_cfg[20];
//     assert_eq!(cur_test.test_id, 20);
//     let obj = create_dummy_obj(
//         make_code_section(cur_test.function_start, &cur_test.function_bytes),
//         Some(make_data_section(cur_test.jump_table_start, &cur_test.jump_table_bytes)),
//     );
//     let mut state = AnalyzerState::default();
//     // section 1 is .text now that we have a relative jump table in .rdata
//     let start_addr = SectionAddress::new(1, cur_test.function_start);
//     // CFA completed with no errors
//     let res = state.process_function_at(&obj, start_addr).unwrap_or_else(|e| panic!("{:?}", e));
//     // we have one more function
//     assert!(res);
//     assert_eq!(state.functions.len(), 1);
//     let func = state.functions.get(&start_addr);
//     assert!(func.is_some());
//     let func = func.unwrap();
//     assert!(func.is_function());
//     // does the detected function end match our expected end?
//     assert_eq!(func.end, Some(start_addr + cur_test.function_bytes.len() as u32));
//     // for this func, we should have 1 jump table
//     assert_eq!(state.jump_tables.is_empty(), false);
//     assert_eq!(state.jump_tables.len(), 1);
//     let jump_table_entry =
//         state.jump_tables.get(&SectionAddress::new(0, cur_test.jump_table_start));
//     assert!(jump_table_entry.is_some());
//     assert_eq!(*jump_table_entry.unwrap(), 10);
//     // TODO: verify basic block count
//     Ok(())
// }
//
// #[test]
// fn test_jump_table_relative_bytes_with_rlwinm_2() -> Result<()> {
//     let test_cfg: Vec<TestConfig> =
//         serde_yaml::from_reader(File::open("assets/tests/cfa_tests.yml")?)?;
//     let cur_test = &test_cfg[21];
//     assert_eq!(cur_test.test_id, 21);
//     let obj = create_dummy_obj(
//         make_code_section(cur_test.function_start, &cur_test.function_bytes),
//         Some(make_data_section(cur_test.jump_table_start, &cur_test.jump_table_bytes)),
//     );
//     let mut state = AnalyzerState::default();
//     // section 1 is .text now that we have a relative jump table in .rdata
//     let start_addr = SectionAddress::new(1, cur_test.function_start);
//     // CFA completed with no errors
//     let res = state.process_function_at(&obj, start_addr).unwrap_or_else(|e| panic!("{:?}", e));
//     // we have one more function
//     assert!(res);
//     assert_eq!(state.functions.len(), 1);
//     let func = state.functions.get(&start_addr);
//     assert!(func.is_some());
//     let func = func.unwrap();
//     assert!(func.is_function());
//     // does the detected function end match our expected end?
//     assert_eq!(func.end, Some(start_addr + cur_test.function_bytes.len() as u32));
//     // for this func, we should have 1 jump table
//     assert_eq!(state.jump_tables.is_empty(), false);
//     assert_eq!(state.jump_tables.len(), 1);
//     let jump_table_entry =
//         state.jump_tables.get(&SectionAddress::new(0, cur_test.jump_table_start));
//     assert!(jump_table_entry.is_some());
//     assert_eq!(*jump_table_entry.unwrap(), 10);
//     // TODO: verify basic block count
//     Ok(())
// }

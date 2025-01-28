/// Topological sort algorithm based on DFS:
/// https://en.wikipedia.org/wiki/Topological_sorting#Depth-first_search
/// Finds either an ordering of the vertices such that all edges go from
/// lower to higher indexed nodes, or a cycle.
///
/// Implementation by Simon Lindholm
/// https://gist.github.com/simonlindholm/08664dd783ad4b9f23532fdd5e352b42
pub fn toposort(graph: &[Vec<usize>]) -> Result<Vec<usize>, Vec<usize>> {
    let n = graph.len();
    #[derive(Copy, Clone)]
    enum State {
        Unvisited,
        Active(usize, usize),
        Finished,
    }
    let mut state = vec![State::Unvisited; n + 1];
    state[n] = State::Active(0, usize::MAX);
    let mut ret = Vec::new();
    let mut cur = n;
    loop {
        let State::Active(eind, par) = state[cur] else { panic!("unexpected state 1") };
        let adj;
        if cur == n {
            if eind == n {
                break;
            }
            adj = eind;
        } else {
            if eind == graph[cur].len() {
                state[cur] = State::Finished;
                ret.push(cur);
                cur = par;
                continue;
            }
            adj = graph[cur][eind];
        };
        state[cur] = State::Active(eind + 1, par);
        match state[adj] {
            State::Unvisited => {
                state[adj] = State::Active(0, cur);
                cur = adj;
            }
            State::Active(..) => {
                let mut cycle = Vec::new();
                while cur != adj {
                    cycle.push(cur);
                    let State::Active(_, par) = state[cur] else { panic!("unexpected state 2") };
                    cur = par;
                }
                cycle.push(cur);
                cycle.reverse();
                return Err(cycle);
            }
            State::Finished => {}
        };
    }
    ret.reverse();
    Ok(ret)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn test_correct() {
        let mut rng_state: usize = 0;
        let mut rand = || {
            rng_state = rng_state.wrapping_mul(123156351724123181_usize);
            rng_state = rng_state.wrapping_add(670143798154186239_usize);
            rng_state >> 32
        };
        for _ in 0..10000 {
            let n = rand() % 20;
            let mut g = vec![vec![]; n];
            let mut g_set = HashSet::new();
            if n != 0 {
                let m = rand() % 50;
                for _ in 0..m {
                    let a = rand() % n;
                    let b = rand() % n;
                    g[a].push(b);
                    g_set.insert((a, b));
                }
            }
            match toposort(&g) {
                Ok(order) => {
                    assert_eq!(order.len(), n);
                    let mut node_to_order = vec![usize::MAX; n];
                    // Every node should occur exactly once...
                    for (i, &node) in order.iter().enumerate() {
                        assert!(node < n);
                        assert_eq!(node_to_order[node], usize::MAX);
                        node_to_order[node] = i;
                    }
                    // and the edges should go in forward order in the list
                    for i in 0..n {
                        for &j in &g[i] {
                            assert!(node_to_order[i] < node_to_order[j]);
                        }
                    }
                }
                Err(cycle) => {
                    // The found cycle should exist in the graph
                    assert!(!cycle.is_empty());
                    for i in 0..cycle.len() {
                        let a = cycle[i];
                        let b = cycle[(i + 1) % cycle.len()];
                        assert!(g_set.contains(&(a, b)));
                    }
                }
            }
        }
    }
}

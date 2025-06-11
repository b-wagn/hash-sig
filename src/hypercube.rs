use dashmap::mapref::one::Ref;
use dashmap::DashMap;
use num_bigint::BigInt;
use num_bigint::BigUint;
use num_traits::One;
use num_traits::ToPrimitive;
use num_traits::Zero;
use once_cell::sync::Lazy;
use std::cmp::{max, min};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::ops::Deref;
use std::sync::Mutex;

/// Max dimension precomputed for layer sizes.
const MAX_DIMENSION: usize = 100;

/// Global caches for binomial coefficients.
static BINOMS: Lazy<Mutex<Vec<Vec<BigUint>>>> = Lazy::new(|| Mutex::new(vec![]));
/// Global caches for layer sizes of base, each has up to dimension `MAX_DIMENSION`.
static ALL_LAYER_SIZES_OF_BASE: Lazy<DashMap<usize, Vec<Vec<BigUint>>>> = Lazy::new(DashMap::new);

/// All layer sizes of base `w` with dimension up to `MAX_DIMENSION`.
struct AllLayerSizes<'a>(Ref<'a, usize, Vec<Vec<BigUint>>>);

impl AllLayerSizes<'_> {
    fn new(w: usize) -> Self {
        if !ALL_LAYER_SIZES_OF_BASE.contains_key(&w) {
            ALL_LAYER_SIZES_OF_BASE
                .entry(w)
                .or_insert_with(|| prepare_layer_sizes(w));
        }
        Self(ALL_LAYER_SIZES_OF_BASE.get(&w).unwrap())
    }
}

impl Deref for AllLayerSizes<'_> {
    type Target = Vec<Vec<BigUint>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Outputs the binomial coefficient binom(n, k) (n choose k)
fn binom(n: usize, k: usize) -> BigUint {
    if k > n {
        return BigUint::from(0u32);
    }
    let binoms = BINOMS.lock().unwrap();
    if binoms.len() < n + 1 {
        panic!("BINOMS cache is empty. Call precompute_local before calling binom.");
    }
    binoms[n][k].clone()
}

/// Compute the number of integer vectors of dimension `n`,
/// with entries in [0, m], that sum to `k`.
/// Equivalent to coefficient of x^k in (1 + x + x^2 + ... + x^m)^n.
///
/// This uses precomputed values if possible.
fn nb(k: usize, m: usize, n: usize) -> BigUint {
    let mut sum = BigInt::zero();
    for s in 0..=k / (m + 1) {
        let part = binom(n, s) * binom(k - s * (m + 1) + n - 1, n - 1);
        let part = BigInt::from(part);
        if s % 2 == 0 {
            sum += part;
        } else {
            sum -= part;
        }
    }
    sum.to_biguint()
        .expect("nb result negative — check parameters")
}

/// Precompute binomials n choose k for n up to v + (w-1)v
fn precompute_binoms(v: usize, w: usize) {
    let max_distance = (w - 1) * v;
    let size = max_distance + v;
    let mut binoms = BINOMS.lock().unwrap();
    for n in binoms.len()..size {
        binoms.push(vec![BigUint::zero(); n + 1]);
        binoms[n][0] = BigUint::one();
        for k in 1..n {
            binoms[n][k] = &binoms[n - 1][k - 1] + &binoms[n - 1][k];
        }
        binoms[n][n] = BigUint::one();
    }
}

/// Load or compute layer sizes up to some `v_max = MAX_DIMENSION`
fn prepare_layer_sizes(w: usize) -> Vec<Vec<BigUint>> {
    let v_max = MAX_DIMENSION;
    let mut all_layers = vec![vec![]; v_max + 1];
    for v in 1..=v_max {
        let max_distance = (w - 1) * v;
        all_layers[v] = vec![BigUint::from(0_u16); max_distance + 1]
    }
    let filename = format!("precompute/layer_sizes_w_{}_v_upto_{}.txt", w, v_max);
    match File::open(filename) {
        Ok(res) => {
            let reader = BufReader::new(res);
            for line in reader.lines() {
                let line = line.expect("correct line");
                let parts: Vec<&str> = line.split(',').collect();
                let v_value = usize::from_str_radix(parts[3].trim(), 10).unwrap();
                let max_distance = (w - 1) * v_value;
                let d_value = usize::from_str_radix(parts[5].trim(), 10).unwrap();
                if d_value > max_distance {
                    continue;
                }
                let l_value = BigUint::parse_bytes(parts[7].trim().as_bytes(), 10).unwrap();
                all_layers[v_value][d_value] = l_value;
            }
        }
        Err(_) => {
            precompute_binoms(v_max, w);
            for v in 1..=v_max {
                let max_distance = (w - 1) * v;
                for i in 0..=max_distance {
                    all_layers[v][i] = nb(i, w - 1, v);
                }
            }
        }
    }
    all_layers
}

/// Map an integer x in [0, layer_size(v, d)) to a vertex in layer d
/// of the hypercube [0, w-1]^v.
///
/// Caller must make sure that precompute_global has been called before.
///
/// The vector that is returned has length v
pub fn map_to_vertex(w: usize, v: usize, d: usize, x: BigUint) -> Vec<u8> {
    let mut x_curr = x;
    let mut out = Vec::with_capacity(v);
    let mut d_curr = d;

    let all_layers = AllLayerSizes::new(w);
    assert!(x_curr < all_layers[v][d]);

    for i in 1..v {
        let mut ji = usize::MAX;
        for j in max(0, d_curr as isize - (w as isize - 1) * (v - i) as isize) as usize
            ..=min(w - 1, d_curr)
        {
            let count = all_layers[v - i][d_curr - j].clone();
            if x_curr >= count {
                x_curr -= count;
            } else {
                ji = j;
                break;
            }
        }
        assert!(ji < w);
        let ai = (w - ji - 1) as u8;
        out.push(ai);
        d_curr -= w - 1 - ai as usize;
    }
    assert!((&x_curr + BigUint::from(d_curr)) < BigUint::from(w));
    out.push((w as u8) - 1 - x_curr.to_usize().expect("Conversion failed") as u8 - d_curr as u8);
    out
}

/// Assuming the caller has called precompute_global(v_max, w) before and 1 <= v <= v_max, this function
/// returns the total size of layers 0 to d (inclusive) in hypercube [0, w-1]^v.
///
/// Caller needs to make sure that d is a valid layer: 0 <= d <= v * (w-1)
pub fn hypercube_part_size(w: usize, v: usize, d: usize) -> BigUint {
    let all_layers = AllLayerSizes::new(w);
    let mut sum = BigUint::zero();
    for l in 0..=d {
        sum += &all_layers[v][l];
    }
    sum
}

/// Assuming the caller has called precompute_global(v_max, w) before and 1 <= v <= v_max, this function
/// finds maximal d such that the total size L_<d of layers 0 to d-1 (inclusive) in hypercube [0, w-1]^v
/// is not bigger than x
///
/// Returns d and x-L_<d
///
/// Caller needs to make sure that x < w^v
pub fn hypercube_find_layer(w: usize, v: usize, x: BigUint) -> (usize, BigUint) {
    let all_layers = AllLayerSizes::new(w);
    let mut d = 0;
    let mut val = x;
    while val >= all_layers[v][d] {
        // Note: this can be replaced with binary search for efficiency
        val -= &all_layers[v][d];
        d += 1;
    }
    return (d, val);
}

/// Map a vertex `a` in layer `d` to its index x in [0, layer_size(v, d)).
///
/// Caller must make sure that precompute_global has been called before.
pub fn map_to_integer(w: usize, v: usize, d: usize, a: &[u8]) -> BigUint {
    assert_eq!(a.len(), v);
    let mut x_curr = BigUint::from(0u32);
    let mut d_curr = w - 1 - a[v - 1] as usize;

    let all_layers = AllLayerSizes::new(w);

    for i in (0..v - 1).rev() {
        let ji = w - 1 - a[i] as usize;
        d_curr += ji;
        for j in max(0, d_curr as isize - (w as isize - 1) * (v - i - 1) as isize) as usize..ji {
            let count = all_layers[v - i - 1][d_curr - j].clone();
            x_curr += count;
        }
    }
    assert_eq!(d_curr, d);
    x_curr
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;
    use num_traits::ToPrimitive;

    #[test]
    fn test_maps() {
        let w = 4;
        let v = 8;
        let d = 20;
        let max_x = AllLayerSizes::new(w)[v][d]
            .clone()
            .to_usize()
            .expect("Conversion failed in test_maps");
        for x_usize in 0..max_x {
            let x = BigUint::from(x_usize);
            let a = map_to_vertex(w, v, d, x.clone());
            let layer: usize = a.iter().map(|&x| x as usize).sum();
            assert_eq!((w - 1) * v - layer, d);
            let y = map_to_integer(w, v, d, &a);
            let b = map_to_vertex(w, v, d, y.clone());
            assert_eq!(x, y);
            assert_eq!(a, b);
        }
    }

    #[test]
    fn test_big_map() {
        let w = 12;
        let v = 40;
        let d = 174;
        let dec_string = b"21790506781852242898091207809690042074412";
        let x = BigUint::parse_bytes(dec_string, 10).expect("Invalid input");
        let a = map_to_vertex(w, v, d, x.clone());
        let y = map_to_integer(w, v, d, &a);
        let b = map_to_vertex(w, v, d, y.clone());
        assert_eq!(x, y);
        assert_eq!(a, b);
    }

    #[test]
    fn test_nb() {
        precompute_binoms(3, 2);
        assert_eq!(nb(0, 1, 3), BigUint::from(1u32));
        assert_eq!(nb(1, 1, 3), BigUint::from(3u32));
        assert_eq!(nb(2, 1, 3), BigUint::from(3u32));
        assert_eq!(nb(3, 1, 3), BigUint::from(1u32));

        precompute_binoms(4, 5);
        assert_eq!(nb(6, 3, 5), BigUint::from(135u32));
        assert_eq!(nb(12, 3, 5), BigUint::from(35u32));
        assert_eq!(nb(2, 3, 5), BigUint::from(15u32));
    }
}

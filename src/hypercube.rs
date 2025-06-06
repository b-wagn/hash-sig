use num_bigint::BigInt;
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use num_traits::Zero;
use once_cell::sync::Lazy;
use std::cmp::{max, min};
use std::sync::Mutex;
use std::fs::File;
use std::io::{BufRead, BufReader};

// Global caches for factorials, binomial coefficients, and layer sizes
static FACTORIALS: Lazy<Mutex<Vec<BigUint>>> = Lazy::new(|| Mutex::new(vec![]));
static BINOMS: Lazy<Mutex<Vec<Vec<BigUint>>>> = Lazy::new(|| Mutex::new(vec![]));
static LAYER_SIZES: Lazy<Mutex<Vec<BigUint>>> = Lazy::new(|| Mutex::new(vec![]));
static ALL_LAYER_SIZES: Lazy<Mutex<Vec<Vec<BigUint>>>> = Lazy::new(|| Mutex::new(vec![]));

/// Outputs the binomial coefficient binom(n, k) (n choose k)
///
/// This assumes that at least the relevant factorials have been precomputed.
fn binom(n: usize, k: usize) -> BigUint {
    if k > n {
        return BigUint::from(0u32);
    }
    let binoms = BINOMS.lock().unwrap();
    if binoms.is_empty() {
        panic!("BINOMS cache is empty. Call precompute_local before calling binom.");
    }
    if binoms[n][k] == BigUint::from(0u32) {
        drop(binoms); // unlock before recomputing
                      // recompute binom if needed, or panic if no factorials
        panic!("binom not precomputed for ({}, {})", n, k);
    } else {
        binoms[n][k].clone()
    }
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

/// Precompute factorials, binomial coefficients, and layer sizes for a given (v, w).
/// The hypercube is [0, w-1]^v.
///
/// Precompute factorials up to v + (w-1)v
/// Precompute binomials n choose k for n up to v + (w-1)v
/// Precompute layer sizes from 0 to (w-1)v
fn precompute_local(v: usize, w: usize) {
    let max_distance = (w - 1) * v;
    let size = max_distance + v;

    // precompute factorials and binoms
    let mut factorials = vec![BigUint::from(0u32); size + 1];
    factorials[0] = BigUint::from(1u32);
    for i in 1..=size {
        factorials[i] = &factorials[i - 1] * BigUint::from(i);
    }
    let mut binoms = vec![vec![BigUint::from(0u32); size]; size];
    for n in 0..size {
        for k in 0..=n {
            binoms[n][k] = &factorials[n] / (&factorials[k] * &factorials[n - k]);
        }
    }
    *FACTORIALS.lock().unwrap() = factorials;
    *BINOMS.lock().unwrap() = binoms;

    // precompute layer sizes
    // note: BINOMS has now been precomputed so we can call the nb function
    let mut layer_sizes = vec![BigUint::from(0u32); max_distance + 1];
    for i in 0..=max_distance {
        layer_sizes[i] = nb(i, w - 1, v);
    }
    *LAYER_SIZES.lock().unwrap() = layer_sizes;
}

/// load or compute layer sizes up to some v_max=100
pub fn load_layer_sizes(w: usize){
    let v_max =100;
    let mut all_layers = vec![vec![];v_max+1];
    for v in 1..=v_max{
        let max_distance = (w-1)*v;
        all_layers[v]= vec![BigUint::from(0 as u16);max_distance+1]
    }
    let filename = format!("precompute/layer_sizes_w_{}_v_upto_{}.txt",w,v_max);
    let res = File::open(filename);
    match res{
        Ok(_)=>{
            let reader = BufReader::new(res.unwrap());
            for line in reader.lines() {
                let line = line.expect("correct line");
                let parts: Vec<&str> = line.split(',').collect();
                let v_value = usize::from_str_radix(parts[3].trim(),10).unwrap();
                //parts[3]                    .trim()                    .parse::<usize>()                    .unwrap();
                let max_distance = (w-1)*v_value;
                let d_value = usize::from_str_radix(parts[5].trim(),10).unwrap();
                if d_value> max_distance{
                    continue;
                }
                let l_value = BigUint::parse_bytes(parts[7].trim().as_bytes(), 10).unwrap();
                all_layers[v_value][d_value] = l_value;
            }
        }
        Err(_)=>{
            for v in 1..=v_max {
                precompute_local(v, w);
                all_layers[v]=LAYER_SIZES.lock().unwrap().clone();
            }
        }
    }
    *ALL_LAYER_SIZES.lock().unwrap() = all_layers;
}

/// Precompute all layer sizes for hypercubes [0, w-1]^v for v in 1..=v_max.
pub fn precompute_global(v_max: usize, w: usize) {
    let mut all_layers = vec![vec![]];
    for v in 1..=v_max {
        precompute_local(v, w);
        all_layers.push(LAYER_SIZES.lock().unwrap().clone());
    }
    *ALL_LAYER_SIZES.lock().unwrap() = all_layers;
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

    let all_layers = ALL_LAYER_SIZES.lock().unwrap();
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
        let ai = (w - ji-1) as u8;
        out.push(ai);
        d_curr -= w - 1- ai  as usize;
    }
    assert!((&x_curr + BigUint::from(d_curr)) < BigUint::from(w));
    out.push((w as u8) - 1- x_curr.to_usize().expect("Conversion failed") as u8 - d_curr as u8);
    out
}

/// Assuming the caller has called precompute_global(v_max, w) before and 1 <= v <= v_max, this function
/// returns the total size of layers 0 to d (inclusive) in hypercube [0, w-1]^v.
///
/// Caller needs to make sure that d is a valid layer: 0 <= d <= v * (w-1)
pub fn hypercube_part_size(v: usize, d: usize) -> BigUint {
    let all_layers = ALL_LAYER_SIZES.lock().unwrap();
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
pub fn hypercube_find_layer(x: BigUint, v: usize) -> (usize, BigUint) {
    let all_layers = ALL_LAYER_SIZES.lock().unwrap();
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
    let mut d_curr = w - 1 -a[v - 1] as usize;

        let all_layers = ALL_LAYER_SIZES.lock().unwrap();

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
        load_layer_sizes(w);
        let max_x = ALL_LAYER_SIZES
            .lock()
            .unwrap()[v][d]
            .clone()
            .to_usize()
            .expect("Conversion failed in test_maps");
        for x_usize in 0..max_x
        {
            let x = BigUint::from(x_usize);
            let a = map_to_vertex(w, v, d, x.clone());
            let layer: usize = a.iter().map(|&x| x as usize).sum();
            assert_eq!((w-1)*v-layer,d);
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
        load_layer_sizes(w);
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
        precompute_local(3, 2);
        assert_eq!(nb(0, 1, 3), BigUint::from(1u32));
        assert_eq!(nb(1, 1, 3), BigUint::from(3u32));
        assert_eq!(nb(2, 1, 3), BigUint::from(3u32));
        assert_eq!(nb(3, 1, 3), BigUint::from(1u32));

        precompute_local(4, 5);
        assert_eq!(nb(6, 3, 5), BigUint::from(135u32));
        assert_eq!(nb(12, 3, 5), BigUint::from(35u32));
        assert_eq!(nb(2, 3, 5), BigUint::from(15u32));
    }
}

use cprf::ggm::GgmRCPrfMasterKey;
use generic_array::GenericArray;

fn main() {
    let key = GenericArray::from([0u8; 16]);
    let mk = GgmRCPrfMasterKey::new(key);
    let mk_output = mk.evaluate(22677);

    let ck = mk.constrained(21233..33231);
    println!("{:?}", ck);
    let ck_output = ck.evaluate(22677).unwrap();

    assert_eq!(mk_output, ck_output);
}

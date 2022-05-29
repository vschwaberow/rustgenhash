use blake2::{Blake2b512, Blake2s256};
use gost94::{Gost94Test, Gost94UA};
use groestl::Groestl256;
use hex_literal::hex;
use md2::Md2;
use md4::Md4;
use md5::Md5;
use ripemd::{Ripemd160, Ripemd320};
use sha1::{Digest, Sha1};
use sha2::{Sha224, Sha256, Sha384, Sha512};
use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
use shabal::{Shabal192, Shabal224, Shabal256, Shabal384, Shabal512};
use streebog::{Streebog256, Streebog512};
use whirlpool::Whirlpool;

const PHRASE: &str = "Jeder wackere Bayer vertilgt bequem zwo Pfund Kalbshaxen.";

#[test]
fn lib_blake2b_hash() {
    let mut hasher = Blake2b512::new();
    hasher.update(PHRASE.as_bytes());
    let result = hasher.finalize();
    assert_eq!(result[..], hex!("95b7ecb0d7de59820205a0a94fe3ca5ee36fd296b1a9ecaa4e01634aed9fa9505d70182c12f900b9dd95f1d5c04fe57dbc5b1e48acdf3a8bae2996f5d8f4578a"));
}

#[test]
fn lib_blake2s_hash() {
    let mut hasher = Blake2s256::new();
    hasher.update(PHRASE.as_bytes());
    let result = hasher.finalize();
    assert_eq!(
        result[..],
        hex!("dbfd3f2c835adcc9fc955d812384bb3bf569de0b9613ffca0e723254c05cf497")
    );
}

#[test]
fn lib_gost94_hash() {
    let mut hasher = Gost94Test::new();
    hasher.update(PHRASE.as_bytes());
    let result = hasher.finalize();
    assert_eq!(
        result[..],
        hex!("1845acc06577ead1f5b671e7e452fc6064e90ab1bbb536df36a91327e40e1872")
    );
}

#[test]
fn lib_gost94ua_hash() {
    let mut hasher = Gost94UA::new();
    hasher.update(PHRASE.as_bytes());
    let result = hasher.finalize();
    assert_eq!(
        result[..],
        hex!("3a8ce1ee676fa5b0c942c0426309b165376e23cc7d826f31944cdc827aaf674a")
    );
}

#[test]
fn lib_groestl_hash() {
    let mut hasher = Groestl256::new();
    hasher.update(PHRASE.as_bytes());
    let result = hasher.finalize();
    assert_eq!(
        result[..],
        hex!("f65cae36b7a0cb51e8ee732f4090ffacaa8f910a793596046073b8457bc4a356")
    );
}

#[test]
fn lib_md2_hash() {
    let mut hasher = Md2::new();
    hasher.update(PHRASE.as_bytes());
    let result = hasher.finalize();
    assert_eq!(result[..], hex!("5e5377610e6b41e7103e7fab19facc07"));
}

#[test]
fn lib_md4_hash() {
    let mut hasher = Md4::new();
    hasher.update(PHRASE.as_bytes());
    let result = hasher.finalize();
    assert_eq!(result[..], hex!("18744ab6124baa392ee1cc9b1552a403"));
}

#[test]
fn lib_md5_hash() {
    let mut hasher = Md5::new();
    hasher.update(PHRASE.as_bytes());
    let result = hasher.finalize();
    assert_eq!(result[..], hex!("ad05bcfc97af63bf7ebf568220b19d7e"));
}

#[test]
fn lib_ripemd160_hash() {
    let mut hasher = Ripemd160::new();
    hasher.update(PHRASE.as_bytes());
    let result = hasher.finalize();
    assert_eq!(result[..], hex!("85b000debad329e4738bfefb0e480d2cb32a0869"));
}

#[test]
fn lib_ripemd320_hash() {
    let mut hasher = Ripemd320::new();
    hasher.update(PHRASE.as_bytes());
    let result = hasher.finalize();
    assert_eq!(
        result[..],
        hex!("e34757b3c51470ec4a47a06a39ffbe85587f41f9711facc25bdcf5d74ebf44e59743ca07bd70ab5e")
    );
}

#[test]
fn lib_sha1_hash() {
    let mut hasher = Sha1::new();
    hasher.update(PHRASE.as_bytes());
    let result = hasher.finalize();
    assert_eq!(result[..], hex!("1C90817FE5067AB226A331D4E7454858F6DD966A"));
}

#[test]
fn lib_sha2_hash() {
    let mut hasher = Sha224::new();
    hasher.update(PHRASE.as_bytes());
    let result = hasher.finalize();
    assert_eq!(
        result[..],
        hex!("89f96bccbae0d803667fee6afdd18e2c7df1c93121a24d5878d92afe")
    );

    let mut hasher = Sha256::new();
    hasher.update(PHRASE.as_bytes());
    let result = hasher.finalize();
    assert_eq!(
        result[..],
        hex!("4c3478a95c7b19f747de6d9a0ac49517e37a1312768dd64093626290e5b3ed79")
    );

    let mut hasher = Sha384::new();
    hasher.update(PHRASE.as_bytes());
    let result = hasher.finalize();
    assert_eq!(result[..], hex!("3ec3a73199b013b9345c59353f6914da13b845bd3a662693be6847355a400dab661840ce826912d539be117b7a48b4df"));

    let mut hasher = Sha512::new();
    hasher.update(PHRASE.as_bytes());
    let result = hasher.finalize();
    assert_eq!(result[..], hex!("6116cb584b74a3998852a9639aaed792029e7d2a7bfb9ac7971233ec1e3e303c2f77ccd70dcdea7ebbb72dc03fe2230571e98b9a8586ed1fb418804f167e4cc3"));
}

#[test]
fn lib_sha3_hash() {
    let mut hasher = Sha3_224::new();
    hasher.update(PHRASE.as_bytes());
    let result = hasher.finalize();
    assert_eq!(
        result[..],
        hex!("a3d42c4ca398f6e3deb5f9829db812ec5683a5e908a2a6b5aca5bc2f")
    );

    let mut hasher = Sha3_256::new();
    hasher.update(PHRASE.as_bytes());
    let result = hasher.finalize();
    assert_eq!(
        result[..],
        hex!("7f3b18201d8a0243af7f0190024211066a91c9579889fc80df52e7981de814ef")
    );

    let mut hasher = Sha3_384::new();
    hasher.update(PHRASE.as_bytes());
    let result = hasher.finalize();
    assert_eq!(result[..], hex!("65161678a1d71a9337c945eddd2a1f702cecf8935a4af2236bba1a6b07041af604c830ab9a86c1725a1123ccfae152f4"));

    let mut hasher = Sha3_512::new();
    hasher.update(PHRASE.as_bytes());
    let result = hasher.finalize();
    assert_eq!(result[..], hex!("8975eb95252573d6575a59d3ee995a50b33c15549370af80a37acef2953d43b957a0c66664e22ac0eacbe7d99ca094b0fcb5a6d3c5a266337d8a23a76a9b846f"));
}

#[test]
fn lib_shabal_hash() {
    let mut hasher = Shabal192::new();
    hasher.update(PHRASE.as_bytes());
    let result = hasher.finalize();
    assert_eq!(
        result[..],
        hex!("2e74a8bae598b18ad03179eed4ddf334f0c8d7bf2062141c")
    );

    let mut hasher = Shabal224::new();
    hasher.update(PHRASE.as_bytes());
    let result = hasher.finalize();
    assert_eq!(
        result[..],
        hex!("5726195b421e6694cd27069e43b0b5fdf470e100680fc0a176e98602")
    );

    let mut hasher = Shabal256::new();
    hasher.update(PHRASE.as_bytes());
    let result = hasher.finalize();
    assert_eq!(
        result[..],
        hex!("2416fcb3074316430af2ee338aba58e1d965f5436fa074eb5a5f22b47ee0a32f")
    );

    let mut hasher = Shabal384::new();
    hasher.update(PHRASE.as_bytes());
    let result = hasher.finalize();
    assert_eq!(result[..], hex!("09491396789f3aba449b147de27d0fe3e79050b6f7cf09e49b4c1bf7ff72630a3122d6618c0ef24333016e4ef990004c"));

    let mut hasher = Shabal512::new();
    hasher.update(PHRASE.as_bytes());
    let result = hasher.finalize();
    assert_eq!(result[..], hex!("40d7579e07ae5df931d64d444abe1d7fa1ba784a8ddba6461bd0825abf6c17dae29d9fe3a3f7b968e537f04a28cd5880ea6954b91f2ded8354febe483125ad06"));
}

#[test]
fn lib_streebog_hash() {
    let mut hasher = Streebog256::new();
    hasher.update(PHRASE.as_bytes());
    let result = hasher.finalize();
    assert_eq!(
        result[..],
        hex!("51526ca01cc97f72fde98a9e45bbd3e4ba54a478ab9a8db550354be5295f9f00")
    );

    let mut hasher = Streebog512::new();
    hasher.update(PHRASE.as_bytes());
    let result = hasher.finalize();
    assert_eq!(result[..], hex!("665ff29a87dca81a48000b95b155e78b84fdb908368f0e125b8946de9835c0239f13984549f48b89a2c35acc5549bc89676848f1f199253e0cfdba3eef2878b8"));
}

#[test]
fn lib_whirlpool_hash() {
    let mut hasher = Whirlpool::new();
    hasher.update(PHRASE.as_bytes());
    let result = hasher.finalize();
    assert_eq!(result[..], hex!("171642cace2dabe6f0aa31c9b425af8ec180e3d569640d81c95d6721e12ece9f7d91271a35dd79d4ccacad7b43cf9446c391fdeb94fc3ba293e2550dbd9b5d10"));
}

import BIP32Factory from "bip32";
import * as ecc from "./r1";
import { BIP32Interface } from "bip32";
// You must wrap a tiny-secp256k1 compatible implementation
const bip32 = BIP32Factory(ecc);

const node: BIP32Interface = bip32.fromBase58(
  "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
);

const child: BIP32Interface = node.derive(0).derive(0);

console.log(child.publicKey.toString('hex'));

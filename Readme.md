# TREDD - Trustless escrow for digital data

This is Tredd,
a software library that allows a buyer and a seller of some information to exchange payment for data securely.

It relies on
[the TxVM blockchain](https://github.com/chain/txvm)
and includes a demonstration client and server
(in
[cmd/tredd](https://github.com/bobg/tredd/tree/master/cmd/tredd)).

A buyer sends a request for some content to a seller.
The seller responds with an encrypted copy of the content.
The seller sends a partial blockchain transaction to the seller,
containing payment for the content.
The seller completes the partial transaction and publishes it to the blockchain.
The completed transaction reveals the decryption key,
which the buyer uses to decrypt the content.
The buyer has a way to claim a refund if the key fails to produce the promised content.

For more information,
see
[this detailed explanation of Tredd’s design and operation](https://docs.google.com/document/d/1eC36V8fX9AVXJDNx1qiCksAj03C9DOp9YCWzIC2wKJE/edit?usp=sharing).

For the motivation behind Tredd, see [Why Tredd](Why.md).

For step-by-step instructions for running the Tredd server and client, see [Trying Tredd](Try.md).

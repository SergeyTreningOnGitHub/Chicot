#pragma once
#include "transaction.h"
#include "crypto.h"

class Block{
    SHA256_Digest prev_block_hash_;
    SHA256_Digest merkle_root_;
    uint32_t timestamp_;
    uint32_t difficulty_;
    ByteMessage nonce_;
    std::vector<Transaction> txs_;

    void calc_merkle_root();
    void collapse_merkle(const std::vector<SHA256_Digest>& hashes);
    ByteMessage concat_hashes(const SHA256_Digest& lhs, const SHA256_Digest& rhs) const;
    ByteMessage header_as_bytes()const;
public:

    ByteMessage Serialize() const;
    void Deserialize(const ByteMessage& msg);
    void AddTx(const Transaction& tx);
    SHA256_Digest GetDigest() const;

};

class Ledger{
    Block cur_block_;
public:

};
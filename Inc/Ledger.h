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
public:

    ByteMessage Serialize() const;
    void Deserialize(const ByteMessage& msg);
};

class Ledger{
    std::vector<Block> blocks;
public:
    
};
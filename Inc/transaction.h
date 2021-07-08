#pragma once
#include "crypto.h"
#include "transaction.capnp.h"
#include <vector>

class Transaction{
    struct Input{
        SHA256_Digest prev_tx_hash_;
        uint16_t out_idx_;
    };

    struct Output{
        uint64_t value_;
        PublicKey pub_key_;
    };

    EC_Sign  ec_sign_;
    std::vector<Input> inputs_;
    std::vector<Output> outputs_;

public:    
    void AddInput(const Input& in);
    void AddOutput(const Output& out);
    const Output& GetOutput(uint16_t idx) const;
    const Input& GetInput(uint16_t idx) const;
    
    ByteMessage Serialize() const;
    void Deserialize(const ByteMessage& msg);
    void Sign();
    SHA256_Digest Hash() const;
};
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

    template<typename INTEGRAL_TYPE>
    ByteMessage as_bytes(INTEGRAL_TYPE val)const{
        ByteMessage res;
        for(uint32_t i = 0;i < sizeof(val);i++){
            res.push_back((val >> i) & 0xFF);
        }
        return res;
    }

    ByteMessage input_as_bytes(const Input& inp) const{
        ByteMessage res;
        copy(inp.prev_tx_hash_.begin(), inp.prev_tx_hash_.end(), back_inserter(res));
        auto integral_bytes = as_bytes(inp.out_idx_);
        copy(integral_bytes.begin(), integral_bytes.end(), back_inserter(res));
        return res;
    }

    ByteMessage output_as_bytes(const Output& out) const {        
        ByteMessage res;
        auto integral_bytes = as_bytes(out.value_);
        copy(integral_bytes.begin(), integral_bytes.end(), back_inserter(res));
        copy(out.pub_key_.begin(), out.pub_key_.end(), back_inserter(res));
        return res;
    }

public:    
    void AddInput(const Input& in);
    void AddOutput(const Output& out);
    const Output& GetOutput(uint16_t idx) const;
    const Input& GetInput(uint16_t idx) const;
    
    ByteMessage Serialize() const;
    void Deserialize(const ByteMessage& msg);
    ByteMessage GetContextForSign() const;
    ByteMessage GetContextForHash() const;
};
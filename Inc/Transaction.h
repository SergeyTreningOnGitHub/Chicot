#pragma once
#include "crypto.h"
#include <cstdint>
#include <algorithm>

class Transaction{
    class Input{
        SHA256_Digest prev_tx_hash_;
        uint16_t out_idx_;
        EC_Sign  ec_sign_;
    public:
        ByteMessage Serialize() const{
            ByteMessage res(1 + prev_tx_hash_.size() + sizeof(out_idx_) + 1 + ec_sign_.size());
            size_t idx = 0;
            res[idx] = (uint8_t)(prev_tx_hash_.size() & 0xFF);
            idx++;
            std::copy(prev_tx_hash_.begin(), prev_tx_hash_.end(), res.begin() + idx);
            idx += prev_tx_hash_.size();
            ByteMessage out_idx_s = Serialize(out_idx_);
            std::copy(out_idx_s.begin(), out_idx_s.end(), res.begin() + idx);
            idx += sizeof(out_idx_);
            
        }
    };

    class Output{
        uint64_t value_;
        PublicKey pub_key_;
    public:
        ByteMessage Serialize() const{
            ByteMessage res(sizeof(value_) + 1 + pub_key_.size());
            size_t idx = 0;
            ByteMessage s_val = Serialize(value_);            
            std::copy(s_val.begin(), s_val.end(), res.begin() + idx);
            idx += sizeof(value_);            
            res[idx] = (uint8_t)(pub_key_.size() & 0xFF);
            idx++;
            std::copy(pub_key_.begin(), pub_key_.end(), res.begin() + idx);
            return res;
        }
    };
};
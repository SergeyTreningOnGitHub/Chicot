#include "ledger.h"
#include "transaction.capnp.h"
#include <capnp/message.h>
#include <capnp/serialize-packed.h>
#include <capnp/serialize.h>
#include <algorithm>

using namespace std;

ByteMessage Block::Serialize() const{
    capnp::MallocMessageBuilder message;
    BlockData::Builder block_builder = message.initRoot<BlockData>();
    capnp::Data::Builder prev_block_hash_builder = block_builder.initPrevBlockHash(prev_block_hash_.size());
    copy(prev_block_hash_.begin(), prev_block_hash_.end(), prev_block_hash_builder.begin());

    capnp::Data::Builder merkle_root_builder = block_builder.initMerkleRoot(merkle_root_.size());
    copy(merkle_root_.begin(), merkle_root_.end(), merkle_root_builder.begin());

    block_builder.setTimestamp(timestamp_);
    block_builder.setDifficulty(difficulty_);

    capnp::Data::Builder nonce_builder = block_builder.initNonce(nonce_.size());
    copy(nonce_.begin(), nonce_.end(), nonce_builder.begin());

    capnp::List<TransactData>::Builder txs_builder = block_builder.initTxs(txs_.size());
    for(size_t i = 0;i < txs_.size();i++){        
        const auto& sign = txs_[i].GetEcSign();

        capnp::Data::Builder  sign_builder = txs_builder[i].initEcSign(sign.size());
        copy(sign.begin(), sign.end(), sign_builder.begin());
    
        capnp::List<TransactData::InputData> ::Builder inps_builder = txs_builder[i].initInputs(txs_[i].CountInputs());     

        for(size_t j = 0;j < txs_[i].CountInputs();j++){
            auto inp_builder = inps_builder[j];
            const auto& inp = txs_[i].GetInput(j);

            inp_builder.setOutIdx(inp.out_idx_);        
            auto prev_tx_hash_builder = inp_builder.initPrevTxHash(inp.prev_tx_hash_.size());
            copy(inp.prev_tx_hash_.begin(), inp.prev_tx_hash_.end(), prev_tx_hash_builder.begin());
        }

        capnp::List<TransactData::OutputData> ::Builder outs_builder = txs_builder[i].initOutputs(txs_[i].CountOutputs());
    
        for(size_t j = 0;j < txs_[i].CountOutputs();j++){
            auto out_builder = outs_builder[j];
            const auto& out = txs_[i].GetOutput(j);

            out_builder.setValue(out.value_);
            auto pub_key_builder = out_builder.initPubKey(out.pub_key_.size());
            copy(out.pub_key_.begin(), out.pub_key_.end(), pub_key_builder.begin());
        }
    }    
    
    auto data = messageToFlatArray(message).asBytes();
    return ByteMessage(data.begin(), data.end());
}

void Block::Deserialize(const ByteMessage& msg){
    const kj::ArrayPtr<const capnp::word> p_message(reinterpret_cast<const capnp::word*>(&(*msg.begin())), 
                                           reinterpret_cast<const capnp::word*>(&(*msg.end())));
    
    capnp::FlatArrayMessageReader mess_reader(p_message);
    
    BlockData::Reader block_reader = mess_reader.getRoot<BlockData>();
    auto prev = block_reader.getPrevBlockHash();
    prev_block_hash_.resize(prev.size());
    copy(prev.begin(), prev.end(), prev_block_hash_.begin());
    
    auto merkle = block_reader.getMerkleRoot();
    merkle_root_.resize(merkle.size());
    copy(merkle.begin(), merkle.end(), merkle_root_.begin());

    timestamp_ = block_reader.getTimestamp();

    difficulty_ = block_reader.getDifficulty();
    auto nonc = block_reader.getNonce();
    nonce_.resize(nonc.size());
    copy(nonc.begin(), nonc.end(), nonce_.begin());

    auto txs_reader = block_reader.getTxs();
    txs_.resize(txs_reader.size());
    for(size_t i = 0;i < txs_.size();i++){
        auto ec_sign_reader = txs_reader[i].getEcSign();
        EC_Sign ec_sign;
        copy(ec_sign_reader.begin(), ec_sign_reader.end(), back_inserter(ec_sign));

        txs_[i].SetEcSign(ec_sign);        
        
        auto inps_reader = txs_reader[i].getInputs();    

        for(size_t j = 0;j < inps_reader.size();j++){
            Transaction::Input inp;
            inp.out_idx_ = inps_reader[j].getOutIdx();

            auto prev_tx_hash_reader = inps_reader[j].getPrevTxHash();
            inp.prev_tx_hash_.resize(prev_tx_hash_reader.size());
            copy(prev_tx_hash_reader.begin(), prev_tx_hash_reader.end(), inp.prev_tx_hash_.begin());

            txs_[i].AddInput(inp);

        }

        auto outs_reader = txs_reader[i].getOutputs();

        for(size_t j = 0;j < outs_reader.size();j++){
            Transaction::Output out;
            out.value_ = outs_reader[j].getValue();        
            auto pub_key_reader = outs_reader[j].getPubKey();

            out.pub_key_.resize(pub_key_reader.size());
            copy(pub_key_reader.begin(), pub_key_reader.end(), out.pub_key_.begin());
            txs_[i].AddOutput(out);
        }
    }
}

ByteMessage Block::header_as_bytes()const{
    capnp::MallocMessageBuilder message;
    BlockData::Builder block_builder = message.initRoot<BlockData>();
    capnp::Data::Builder prev_block_hash_builder = block_builder.initPrevBlockHash(prev_block_hash_.size());
    copy(prev_block_hash_.begin(), prev_block_hash_.end(), prev_block_hash_builder.begin());

    capnp::Data::Builder merkle_root_builder = block_builder.initMerkleRoot(merkle_root_.size());
    copy(merkle_root_.begin(), merkle_root_.end(), merkle_root_builder.begin());

    block_builder.setTimestamp(timestamp_);
    block_builder.setDifficulty(difficulty_);

    capnp::Data::Builder nonce_builder = block_builder.initNonce(nonce_.size());
    copy(nonce_.begin(), nonce_.end(), nonce_builder.begin());

    auto data = messageToFlatArray(message).asBytes();
    return ByteMessage(data.begin(), data.end());
}

ByteMessage Block::concat_hashes(const SHA256_Digest& lhs, const SHA256_Digest& rhs) const{
    ByteMessage res;
    res.reserve(lhs.size() + rhs.size());
    std::copy(lhs.begin(), lhs.end(), back_inserter(res));
    std::copy(rhs.begin(), rhs.end(), back_inserter(res));
    return res;
}

void Block::collapse_merkle(const vector<SHA256_Digest>& hashes){
    if(hashes.size() == 1){
        merkle_root_ = hashes[0];
        return;
    }

    vector<SHA256_Digest> collapsed_hashes;

    for(size_t i = 0;i < hashes.size();i += 2){
        if(i == hashes.size() - 1){
            collapsed_hashes.push_back(GenDigest(concat_hashes(hashes[i], hashes[i])));
        }else{
            collapsed_hashes.push_back(GenDigest(concat_hashes(hashes[i], hashes[i + 1])));
        }
    }

    collapse_merkle(collapsed_hashes);
}

void Block::calc_merkle_root(){
    vector<SHA256_Digest> hashes;
    for(const auto& tx : txs_){
        hashes.push_back(GenDigest(tx.Serialize()));
    }

    collapse_merkle(hashes);
}

void Block::AddTx(const Transaction& tx){
    txs_.push_back(tx);
    calc_merkle_root();    
}


SHA256_Digest Block::GetDigest() const{
    return GenDigest(header_as_bytes());
}

bool Block::IsProvedOfWork() const{
    
}
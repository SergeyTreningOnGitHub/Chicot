#include "transaction.h"
#include "transaction.capnp.h"
#include <capnp/message.h>
#include <capnp/serialize-packed.h>
#include <capnp/serialize.h>
#include <algorithm>

using namespace std;

void Transaction::AddInput(const Transaction::Input& in){
    inputs_.push_back(in);
}

void Transaction::AddOutput(const Transaction::Output& out){
    outputs_.push_back(out);
}

const Transaction::Output& Transaction::GetOutput(uint16_t idx) const{
    if(idx >= outputs_.size())
        EXIT_WITH_MSG("index out of range");
    
    return outputs_[idx];
}

const Transaction::Input& Transaction::GetInput(uint16_t idx) const{
    if(idx >= inputs_.size())
        EXIT_WITH_MSG("index out of range");
    
    return inputs_[idx];
}

ByteMessage Transaction::Serialize() const{
    capnp::MallocMessageBuilder message;
    TransactData::Builder transact = message.initRoot<TransactData>();
    capnp::Data::Builder  sign = transact.initEcSign(ec_sign_.size());
    copy(ec_sign_.begin(), ec_sign_.end(), sign.begin());
    
    capnp::List<TransactData::InputData> ::Builder inps = transact.initInputs(inputs_.size());     

    for(size_t i = 0;i < inps.size();i++){
        auto inp = inps[i];
        inp.setOutIdx(inputs_[i].out_idx_);        
        auto prev_tx_hash = inp.initPrevTxHash(inputs_[i].prev_tx_hash_.size());
        copy(inputs_[i].prev_tx_hash_.begin(), inputs_[i].prev_tx_hash_.end(), prev_tx_hash.begin());
    }

    capnp::List<TransactData::OutputData> ::Builder outs = transact.initOutputs(outputs_.size());
    for(size_t i = 0;i < outs.size();i++){
        auto out = outs[i];
        out.setValue(outputs_[i].value_);
        auto pub_key = out.initPubKey(outputs_[i].pub_key_.size());
        copy(outputs_[i].pub_key_.begin(), outputs_[i].pub_key_.end(), pub_key.begin());
    }
    
    auto data = messageToFlatArray(message).asBytes();
    return ByteMessage(data.begin(), data.end());
}

void Transaction::Deserialize(const ByteMessage& msg){
    const kj::ArrayPtr<const capnp::word> p_message(reinterpret_cast<const capnp::word*>(&(*msg.begin())), 
                                           reinterpret_cast<const capnp::word*>(&(*msg.end())));
    
    capnp::FlatArrayMessageReader mess_reader(p_message);
    
    TransactData::Reader transact = mess_reader.getRoot<TransactData>();
    auto sign = transact.getEcSign();

    ec_sign_.resize(sign.size());
    copy(sign.begin(), sign.end(), ec_sign_.begin());

    auto inps = transact.getInputs();
    for(size_t i = 0;i < inps.size();i++){
        inputs_[i].out_idx_ = inps[i].getOutIdx();
        auto prev_tx_hash = inps[i].getPrevTxHash();

        inputs_[i].prev_tx_hash_.resize(prev_tx_hash.size());
        copy(prev_tx_hash.begin(), prev_tx_hash.end(), inputs_[i].prev_tx_hash_.begin());
    }

    auto outs = transact.getOutputs();
    for(size_t i = 0;i < outs.size();i++){
        outputs_[i].value_ = outs[i].getValue();
        auto pub_key = outs[i].getPubKey();

        outputs_[i].pub_key_.resize(pub_key.size());
        copy(pub_key.begin(), pub_key.end(), outputs_[i].pub_key_.begin());
    }
}

ByteMessage Transaction::GetContextForSign() const{
    ByteMessage res;
    for(const auto& inp : inputs_){
        auto input_bytes = input_as_bytes(inp);
        copy(input_bytes.begin(), input_bytes.end(), back_inserter(res));
    }

    for(const auto& out : outputs_){
        auto output_bytes = output_as_bytes(out);
        copy(output_bytes.begin(), output_bytes.end(), back_inserter(res));
    }

    return res;    
}

ByteMessage Transaction::GetContextForHash() const{
    ByteMessage res;
    copy(ec_sign_.begin(), ec_sign_.end(), back_inserter(res));
    auto context_for_sign = GetContextForSign();
    
    copy(context_for_sign.begin(), context_for_sign.end(), back_inserter(res));
    return res;    
}
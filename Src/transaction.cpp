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
    TransactData::Builder tx_builder = message.initRoot<TransactData>();
    capnp::Data::Builder  sign_builder = tx_builder.initEcSign(ec_sign_.size());
    copy(ec_sign_.begin(), ec_sign_.end(), sign_builder.begin());
    
    capnp::List<TransactData::InputData> ::Builder inps_builder = tx_builder.initInputs(inputs_.size());     

    for(size_t i = 0;i < inps_builder.size();i++){
        auto inp_builder = inps_builder[i];
        inp_builder.setOutIdx(inputs_[i].out_idx_);        
        auto prev_tx_hash_builder = inp_builder.initPrevTxHash(inputs_[i].prev_tx_hash_.size());
        copy(inputs_[i].prev_tx_hash_.begin(), inputs_[i].prev_tx_hash_.end(), prev_tx_hash_builder.begin());
    }

    capnp::List<TransactData::OutputData> ::Builder outs_builder = tx_builder.initOutputs(outputs_.size());
    for(size_t i = 0;i < outs_builder.size();i++){
        auto out_builder = outs_builder[i];
        out_builder.setValue(outputs_[i].value_);
        auto pub_key_builder = out_builder.initPubKey(outputs_[i].pub_key_.size());
        copy(outputs_[i].pub_key_.begin(), outputs_[i].pub_key_.end(), pub_key_builder.begin());
    }
    
    auto data = messageToFlatArray(message).asBytes();
    return ByteMessage(data.begin(), data.end());
}

void Transaction::Deserialize(const ByteMessage& msg){
    const kj::ArrayPtr<const capnp::word> p_message(reinterpret_cast<const capnp::word*>(&(*msg.begin())), 
                                           reinterpret_cast<const capnp::word*>(&(*msg.end())));
    
    capnp::FlatArrayMessageReader mess_reader(p_message);
    
    TransactData::Reader tx_reader = mess_reader.getRoot<TransactData>();
    auto sign_reader = tx_reader.getEcSign();

    ec_sign_.resize(sign_reader.size());
    copy(sign_reader.begin(), sign_reader.end(), ec_sign_.begin());

    auto inps_reader = tx_reader.getInputs();    

    for(size_t i = 0;i < inps_reader.size();i++){
        Transaction::Input inp;
        inp.out_idx_ = inps_reader[i].getOutIdx();

        auto prev_tx_hash_reader = inps_reader[i].getPrevTxHash();
        inp.prev_tx_hash_.resize(prev_tx_hash_reader.size());
        copy(prev_tx_hash_reader.begin(), prev_tx_hash_reader.end(), inp.prev_tx_hash_.begin());

        AddInput(inp);

    }

    auto outs_reader = tx_reader.getOutputs();

    for(size_t i = 0;i < outs_reader.size();i++){
        Transaction::Output out;
        out.value_ = outs_reader[i].getValue();        
        auto pub_key_reader = outs_reader[i].getPubKey();

        out.pub_key_.resize(pub_key_reader.size());
        copy(pub_key_reader.begin(), pub_key_reader.end(), out.pub_key_.begin());
        AddOutput(out);
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

size_t Transaction::CountInputs() const{
    return inputs_.size();
}


size_t Transaction::CountOutputs() const{
    return outputs_.size();
}
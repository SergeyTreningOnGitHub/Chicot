@0xb1910c391a66b953;

struct TransactData{
    outputs @0 : List(OutputData);
    inputs  @1 : List(InputData);
    ecSign  @2 : Data;

    struct InputData{
        prevTxHash @0 : Data;
        outIdx @1 : UInt16;        
    }

    struct OutputData{
        value @0:  UInt64;
        pubKey @1: Data;
    }
}

struct BlockData{
    prevBlockHash @0: Data;
    merkleRoot    @1: Data;
    timestamp     @2: UInt32;
    difficulty    @3: UInt32;
    nonce         @4: Data;
    txs           @5: List(TransactData);
}

struct LedgerData{
    blocks @0: List(BlockData);
}
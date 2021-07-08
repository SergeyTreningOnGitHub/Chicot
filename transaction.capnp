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
@0xb1910c391a66b953;

struct Transaction{
    outputs @0 : List(Output);
    inputs  @1 : List(Input);

    struct Output{
        prevTxHash @0 : Data;
        outIdx @1 : UInt16;
        ecSign @2 : Data;
    }

    struct Input{
        value @0:  UInt64;
        pubKey @1: Data;
    }
}
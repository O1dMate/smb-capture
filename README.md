# What is this?
Simple, lightweight modules for capturing the hash from an SMB connection. For purposes such as pen-testing where only the NetNTLMv2 hash is required. This is not a full on SMB server, it stops communicating after capturing the hash.

<br>


# Installation
```
npm i smb-capture
```

<br>

# Usage

1. Install & import the library.
2. Create a new instance of the SMB Server.
3. Setup desired callbacks listeners (see below).
4. Start the server.

There are 4 callbacks that you can setup for the server (all of which are optional):
 * `request` - Called when a SMB request is received. The processed data will be returned as an Object.
 * `error` - Called whenever an error is thrown by the server. The error object is returned.
 * `start` - Called when the SMB server is started.
 * `stop` - Called when the SMB server is stopped.

`Note`: Stopping the server then starting it again is totally fine and supported. All your previously setup callbacks will still work after the server has been stopped and started again.

<br>

## Listening for Connections
```javascript
// This is will also work
// const smb = require('smb-capture');
// const smbServer = new smb.SMBServer();

const { SMBServer } = require('smb-capture');
const smbServer = new SMBServer();

smbServer.on('request', (data) => {
    console.log('Data:', data);
    /* Example:
        {
            username: 'Bob',
            hostname: 'BOB-PC',
            domain: 'example.net',
            net_ntlm_v2_hash: 'Bob::example.net:4141414141414141:1234567890abcdef1234567890abcdef:010100000000000080184a17ec022fc8781adbcf08bdb066830923e4b9e1d4e963f94ec14aa2de8873d6c953a24897b8c2a77ecfa21f330fd5ecbea8382abeed54eb508da911d920f0b11972fa73e715ed057c7644f29d60d2d300ce64a32b8a4b03eec0aeddcea4305e1f32693d9e736623b355129644d41263077e34907ac1e114db4ea9debc3be6e72b7d9ec104384d926190d8b040a939e62066003dc52588a9765b9a8cc6a0416f6ce9026f22889387be64e3ca463645e2f4e0bc5f4f5e30f21f0be37b561f8ce934aea1aac41c7424eb60bb0af00bd83632dcea4895b5028550c3bb8a3cbfb9a2203c59ed2c46c0000000000000000000',
        }
    */
})

smbServer.on('error', (err) => {
    console.log('An Error Occurred:', err);
})

smbServer.on('start', () => {
    console.log('SMB server started');
});

smbServer.on('stop', () => {
    console.log('SMB server stopped');
});

smbServer.start();

// This will stop the server.
// smbServer.stop();
```

<br>

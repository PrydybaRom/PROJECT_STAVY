"use strict"

document.getElementById('submit').onclick = function(){
    let login = document.getElementById("logins").value;
    let password = document.getElementById("passwords").value;
    console.log(login);
    console.log(password);
    
    if (login == "admin" && password == "admin123"){
        window.open('http://127.0.0.1:5000/adminca','_blank');
    }
        
}

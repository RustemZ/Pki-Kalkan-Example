/* 
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

function loadApplet() {
    if ((typeof($iolaapp) != 'undefined') && ($iolaapp != null)) {
        $iolaapp.empty();
        $iolaapp=null;
    }
    $iolaapp = $('<applet width="1" height="1"'
    +' codebase= "applet/"'
    +' code="kz.gov.pki.knca.applet.MainApplet"'
    +' archive="knca_applet.jar"'
    +' type="application/x-java-applet"'
    +' mayscript="true"'
    +' id="KncaApplet" name="KncaApplet">'
    +'<param name="code" value="kz.gov.pki.knca.applet.MainApplet">'
    +'<param name="archive" value="knca_applet.jar">'
    +'<param name="mayscript" value="true">'
    +'<param name="scriptable" value="true">'
   // +'<param name="language" value="ru">'
    +'<param name="separate_jvm" value="true">'
    +'</applet>');
    
//    $('body').append($iolaapp);
    make_log('err', 'Загрузить апплет', 'Результат не известен. Предпологаем что не получилось.')
}

function AppletIsReady() {
    console.log('KncaApplet  is loaded.' );
    make_log('info', 'Загрузить апплет', 'Успешно')
}


function btn_selectKeyFile(){
    // console.log('--- btn_selectKeyFile ---');
    try {
          var appletResult = $iolaapp.get(0).showFileChooser("ALL", "");
          if (appletResult.getErrorCode() === "NONE") {
                    var path =  appletResult.getResult();
                    $('#txt_private_key_path').val( path ); 
                    //console.log('applet2: selectP12File ' + appletResult.path );    
                    make_log('info', 'Выбор ключа', 'Успешно');
           } else {
                $('#txt_private_key_path').val( '' );      
                make_log('err', 'Выбор ключа', 'Ошибка апплета ('+appletResult.getErrorCode()+') ');
           }
    } catch (e) {
       make_log('err', 'Выбор ключа', 'Ошибка javaScript ('+e.name+') '+e.message);
    }

}

function make_log(type, command, message ){
    
    $('#info_command').text(command);
    $('#info_message').text(message);
    if (type==='err'){
      if ($('#info_command').hasClass( "ldw-log-info" )) {
          $('#info_command').removeClass("ldw-log-info");
          $('#info_message').removeClass("ldw-log-info");
      }
      $('#info_command').addClass("ldw-log-error");
      $('#info_message').addClass("ldw-log-error");
    } else {
      if ($('#info_command').hasClass( "ldw-log-error" )) {
          $('#info_command').removeClass("ldw-log-error");
          $('#info_message').removeClass("ldw-log-error");
      }
      $('#info_command').addClass("ldw-log-info");
      $('#info_message').addClass("ldw-log-info");
    }
    

}

   function messageForSignature(type, message){
       make_log( type, 'Подписать' ,message );
   }

   function getAlias2(storageAlias, storagePath, password) {
                var keyType = "";

                if (storagePath !== null && storagePath !== "" && storageAlias !== null && storageAlias !== "") {
                    if (password !== null && password !== "") {
                        appletResult = $iolaapp[0].getKeys(storageAlias, storagePath, password, keyType);
                        if (appletResult.getErrorCode() === "NONE") {
                            var list = appletResult.getResult();
                            var slotListArr = list.split("\n");
                            if ( slotListArr.length===0 || slotListArr[0] === null || slotListArr[0] === "") {
                                    messageForSignature("err", "В хранилище не найдены ключи."  );
                                    return null;
                                }
                            return slotListArr[0].split("|")[3];
                        }
                        else {
                            if (appletResult.getErrorCode() === "WRONG_PASSWORD" && appletResult.getResult() > -1) {
                                messageForSignature("err", "Неправильный пароль! Количество оставшихся попыток: " + appletResult.getResult());
                                return null;
                            } else if (appletResult.getErrorCode() === "WRONG_PASSWORD") {
                                messageForSignature("err", "Неправильный пароль!");
                                return null;
                            } else {
                                messageForSignature("err", appletResult.getErrorCode());
                                return null;
                            }
                        }
                    } else {
                        messageForSignature("err", "Введите пароль к хранилищу");
                        return null;
                    }
                } else {
                    messageForSignature("err", "Не выбран хранилище!");
                    return null;
                }
  }



function   btn_makeSignature() {
        try {
                var data = $("#txt_userMessage").val();
                var storageAlias = "PKCS12"; 
                var storagePath = $("#txt_private_key_path").val(); 
                var password = $("#txt_key_password").val(); 
                var alias = getAlias2(storageAlias, storagePath, password); 
                
                if (storagePath !== null && storagePath !== "" && storageAlias !== null && storageAlias !== "") {
                    if (password !== null && password !== "") {
                        if (alias !== null && alias !== "") {
                            if (data !== null && data !== "") {
                                var certInfo = getCertInfo(storageAlias, storagePath, password, alias  );
                                if (certInfo==null) { return;}
                                var appletResult = $iolaapp[0].createCMSSignature(storageAlias, storagePath, alias, password, data, false);
                                if (appletResult.getErrorCode() === "NONE") {
                                    certInfo["data"]= data;
                                    certInfo["signature"]= appletResult.getResult();
                                    var result = JSON.stringify(certInfo);
                                    $('#txt_userMessageSigned').text( result );
                                    messageForSignature("info", "Успешно");
                                }
                                else {
                                    if (appletResult.getErrorCode() === "WRONG_PASSWORD" && appletResult.getResult() > -1) {
                                        messageForSignature("err", "Неправильный пароль! Количество оставшихся попыток: " + appletResult.getResult());
                                    } else if (appletResult.getErrorCode() === "WRONG_PASSWORD") {
                                        messageForSignature("err", "Неправильный пароль!");
                                    } else {
                                        messageForSignature("err", "Ошибка формирования подписи : "+appletResult.getErrorCode());
                                    }
                                }
                            }
                            else {
                                messageForSignature("err", "Нет данных для сохранения!" );
                            }
                        } 
                    } else {
                        messageForSignature("err", "Введите пароль к файлу с закрытым ключем!");
                    }
                } else {
                    messageForSignature("err", "Не выбран файл с закрытым ключем!");
                }
    } catch (e) {
       messageForSignature('err', 'Ошибка javaScript ('+e.name+') '+e.message);
    }
}

function  messageForServerCheck(type, message){
       make_log( type, 'Проверить' ,message );
       
}

function removePrefix(binOrIin) {
    if ((typeof binOrIin === 'string') && (binOrIin.length>3)) {
        return binOrIin.substr(3);
    } else {
        messageForSignature("err", "Переменая binOrIin не строка с БИН или ИИН. " );
        return null;
    }
}

function getCertInfo(  storageAlias, 
                 storagePath, 
                 password, 
                 alias 
){
    var BIN ="2.5.4.11";
    var IIN ="2.5.4.5";
    var NAME ="2.5.4.3"
    var rwName = $iolaapp[0].getRdnByOid(storageAlias, storagePath, alias, password, NAME, 0);
    var rwBin = $iolaapp[0].getRdnByOid(storageAlias, storagePath, alias, password, BIN, 0);
    if (rwBin.getErrorCode() === "NONE") {
       if (removePrefix(rwBin.getResult())==null)  {return null;}
       return { "binOrIin" : removePrefix(rwBin.getResult()) , "respCode" : 1, "name" : rwName.getResult() };
    } else { 
       var rwIin = $iolaapp[0].getRdnByOid(storageAlias, storagePath, alias, password, IIN, 0);     
       if (rwIin.getErrorCode() === "NONE") {
           if (removePrefix(rwIin.getResult())==null)  {return null;}
           return { "binOrIin" : removePrefix(rwIin.getResult()) , "respCode" : 2, "name" : rwName.getResult() }; ;
       }
       else{
            messageForSignature("err", "Немогу получить БИН или ИИН из сертификата. Ошибка :"+rwIin.getErrorCode() );
            return null;
       }
       
    }

    
}

function btn_checkSignature(){
  $.ajax({
    type: "POST",
    url: "app/save",
    data:  $('#txt_userMessageSigned').val() ,
    success: function( serverAnswer , status ) {
        if (serverAnswer.result==='ok') {
            messageForServerCheck('info', 'Успешно');
        } else{
            messageForServerCheck('err', serverAnswer.errorMsg);
        }
       // console.log(serverAnswer);
    },   
    dataType: "json",
    contentType: "application/json",
    error : function(jqXHR, textStatus, errorThrown) {
       var errMsg = 'Ошибка при выполнений POST-запроса: '+textStatus+'.  '+errorThrown;
       messageForServerCheck( 'err', errMsg ); 
     }
  });
    
    
}

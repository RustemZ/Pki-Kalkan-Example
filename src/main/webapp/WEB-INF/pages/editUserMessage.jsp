<%-- 
    Document   : editUserMessage
    Created on : Sep 1, 2015, 7:23:14 PM
    Author     : r.zhunusov
--%>

<%@page contentType="text/html" pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
        <title>Kalkan using example.</title>
        
        <link type="text/css" rel="stylesheet" charset="UTF-8" href="css/kalkan-applet-using.css">
        <script type="text/javascript" src="js/kalkan-applet-using.js"></script>
        <script src="http://code.jquery.com/jquery-1.11.3.min.js"></script>
    </head>
    <body>
        <h3>Тестирование работы Kalkan.</h3>
      <table >
   <tr><td>-</td>
       <td>Логирование результатов Ваших команд:</td>
       <td> <p>Команда: <span id="info_command">Здесь буду писать имя кнопки котрорые Вы нажимаете</span></p> 
            <p>Результат: <span id="info_message">Здесь буду писать успешно ли завершилась команда или текст ошибки</span></p>
       </td>
   </tr>
   <tr><td>1</td>
       <td>Наберите текст который будете подписывать</td>
       <td> <textarea rows="5" cols="65" name="text" id="txt_userMessage">Тестовое сообщение </textarea> </td>
   </tr>
   <tr><td>2</td>
       <td>Попробуйте вначале загрузить апплет "Kalkan" </td>
       <td> <input type="button"  id="btn_loadApplet" onclick="loadApplet();" value="Загрузить апплет"/>   </td>
   </tr>
   <tr><td>3</td>
       <td> <p>Используя кнопку <span class="ldw-btn-in-text">"Выбор ключа"</span> укажите путь к файлу закрытым ключем</p> 
            <p><input type="input" id="txt_private_key_path" value="" required="true" readonly="true" size="105" class="ldw-txt-private-key"/></p> 
            <p>А также укажите Пароль для  этого ключа : <input type="password"  id="txt_key_password" /> </p> 
       </td>
       <td><input type="button" id="btn_selectKeyFile" onclick="btn_selectKeyFile();" value="Выбор ключа"/> </td>
   </tr>
   <tr>
       <td>4</td>
       <td><p>Пробуем подписать сообщение ключем с помощью кнопки <span class="ldw-btn-in-text">"Подписать"</span>.<br/> 
               Внизу расположена полученная в результате json-строка сообщения с подписью.<br/>
           Именно это json-строка отправиться на сервер.<br/> Так что если Вы внесете в неё изменения, то сервер должен
           прислать ошибку.</p>
           <textarea rows="5" cols="65" name="text" id="txt_userMessageSigned"></textarea>
       </td>
       <td> <input type="button" id="btn_makeSignature"  onclick="btn_makeSignature();" value="Подписать"/>   </td>
   </tr>
   <tr>
       <td>5</td>
       <td>Послать подписанное сообщение на сервер для его проверки с помощью кнопки <span class="ldw-btn-in-text">"Проверить"</span></td>
       <td> <input type="button" id="btn_checkSignature"  onclick="btn_checkSignature();" value="Проверить"/>  </td>
   </tr>

   
  </table>
        
    </body>
</html>

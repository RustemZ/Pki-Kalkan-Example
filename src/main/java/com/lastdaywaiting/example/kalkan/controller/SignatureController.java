/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.lastdaywaiting.example.kalkan.controller;

import com.lastdaywaiting.example.kalkan.model.UserMessage;
import com.lastdaywaiting.example.kalkan.service.SecureManager;
import java.util.HashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/**
 *
 * @author Rustem.Zhunusov_at_gmail.com
 */
@RestController
    public class SignatureController {
    
    
    @RequestMapping(value = "/save", method = RequestMethod.POST ) // , consumes = "application/json"
//    public @ResponseBody String saveUserMassage(@RequestBody  UserMessageK message){
    public @ResponseBody Map<String,String> saveUserMassage(@RequestBody  UserMessage message){
        if (message == null) {
            throw new RuntimeException("Нельзя записать сообщение которого нет.");
        }
        
        // В данном примере параметры БинИлиИин, Имя респоднента и Тип респондента передаються на прямую в запросе 
        // Хотя в реальном приложений они должны браться из сертификата в клиентской сессий 
        //  для этого Вам необходимо настроить конфирурацию SSL на сервере и обращаться к нему по протоколу HTTPS 
        SecureManager secureManager = new SecureManager(message.getBinOrIin(), message.getName(), message.getRespCode() );
        System.out.println( message );
        Map<String,String> result = new HashMap<String,String>();
        if (secureManager.isGoodSignature( message.getData(), message.getSignature()) ) {
            result.put("result", "ok");
            result.put("errorMsg", "Подпись данных валидна.");
        } else{
            result.put("result", "error");
            result.put("errorMsg", secureManager.getLastErrorMsg() );
        
        }
        // Другая бизнесс- логи должна  вызваться здесь
        // например someService.saveMessage(message.getData(), message.getSignature());

        return result;
    }
    
    @RequestMapping(value = "/test", method = RequestMethod.GET ) 
    @ResponseBody
    public String test(){
        return "{\"result\":\"Ok\", \"error\":\"NONE\" }"; 
    }
    
}

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.lastdaywaiting.example.kalkan.model;

import java.io.Serializable;

/**
 * 
 * @author Rustem.Zhunusov_at_gmail.com
 */
public class UserMessage implements Serializable{
    private static final long serialVersionUID = 1L;
    private String data;
    private String signature;
    private String binOrIin;
    private Integer respCode;
    private String name ;

    public UserMessage(String data, String signature) {
        this.data = data;
        this.signature = signature;
    }

    public UserMessage() {
    }
    
    public String getData() {
        return data;
    }

    public void setData(String data) {
        this.data = data;
    }

    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    public String getBinOrIin() {
        return binOrIin;
    }

    public void setBinOrIin(String binOrIin) {
        this.binOrIin = binOrIin;
    }

    public Integer getRespCode() {
        return respCode;
    }

    public void setRespCode(Integer respCode) {
        this.respCode = respCode;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        return "UserMessage{" + " binOrIin=" 
                + binOrIin + ", respCode=" + respCode 
                + ", name=" + name 
                + ", data=" + data + ", signature=" + signature + '}';
    }

    
    
    
}

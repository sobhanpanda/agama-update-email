package org.gluu.agama.user;

import java.util.Map;
import org.gluu.agama.update.JansEmailUpdate;



public abstract class EmailUpdate {
    public abstract String addNewUser(Map<String, String> profile) throws Exception;

    public abstract boolean usernamePolicyMatch(String userName);

    public abstract boolean passwordPolicyMatch(String userPassword);

    public abstract String updateUser(Map<String, String> profile) throws Exception;

    public abstract String sendEmail(String to);

    public abstract Map<String, String> getUserEntityByInum(String inum);

    public static EmailUpdate getInstance(){
        return  JansEmailUpdate.getInstance();
    }    
}

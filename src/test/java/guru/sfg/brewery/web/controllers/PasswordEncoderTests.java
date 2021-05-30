package guru.sfg.brewery.web.controllers;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.ldap.LdapProperties;
import org.springframework.security.core.parameters.P;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.LdapShaPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.StandardPasswordEncoder;

import javax.naming.ldap.LdapContext;

public class PasswordEncoderTests {
    static final String PASSWORD="password";

    @Test
    void bcrypt() {
        PasswordEncoder bcrypt =  new BCryptPasswordEncoder();
        System.out.println(bcrypt.encode(PASSWORD));
        String newValue = bcrypt.encode(PASSWORD);
        Assertions.assertTrue(bcrypt.matches(PASSWORD, newValue));
    }

    @Test
    void testLdap(){
        PasswordEncoder ldap = new LdapShaPasswordEncoder();
        System.out.println(ldap.encode(PASSWORD));
        String newValue = ldap.encode(PASSWORD);
        Assertions.assertTrue(ldap.matches(PASSWORD, newValue));
    }

    @Test
    void testSha256(){
        PasswordEncoder sha256  = new StandardPasswordEncoder();
        String value1 = sha256.encode(PASSWORD);
        String value2 = sha256.encode(PASSWORD);
        System.out.println(value1 + " " +  value2);
    }
}

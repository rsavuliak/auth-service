package com.example.authservice.service;

import com.example.authservice.event.PasswordResetEmailEvent;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

@Component
public class PasswordResetEmailListener {

    private final EmailService emailService;

    public PasswordResetEmailListener(EmailService emailService) {
        this.emailService = emailService;
    }

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void onPasswordResetEmailEvent(PasswordResetEmailEvent event) {
        emailService.sendPasswordResetEmail(event.email(), event.token());
    }
}

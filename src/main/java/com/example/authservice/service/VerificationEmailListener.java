package com.example.authservice.service;

import com.example.authservice.event.VerificationEmailEvent;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

@Component
public class VerificationEmailListener {

    private final EmailService emailService;

    public VerificationEmailListener(EmailService emailService) {
        this.emailService = emailService;
    }

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void onVerificationEmailEvent(VerificationEmailEvent event) {
        emailService.sendVerificationEmail(event.email(), event.token());
    }
}

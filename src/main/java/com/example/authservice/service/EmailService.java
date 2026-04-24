package com.example.authservice.service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

@Service
public class EmailService {

    private static final Logger log = LoggerFactory.getLogger(EmailService.class);

    private final JavaMailSender mailSender;

    @Value("${app.base-url}")
    private String baseUrl;

    @Value("${app.frontend-url}")
    private String frontendUrl;

    @Value("${spring.mail.username}")
    private String fromAddress;

    public EmailService(JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }

    @Async
    public void sendVerificationEmail(String toEmail, String token) {
        String link = baseUrl + "/api/v1/auth/verify-email?token=" + token;
        String html = """
                <div style="font-family:sans-serif;max-width:480px;margin:auto">
                  <h2>Verify your email</h2>
                  <p>Click the button below to activate your account. The link expires in 60 minutes.</p>
                  <a href="%s" style="display:inline-block;padding:12px 24px;background:#000;color:#fff;
                     text-decoration:none;border-radius:6px;font-weight:bold">Verify email</a>
                  <p style="margin-top:16px;color:#666;font-size:13px">
                    Or copy this link:<br><a href="%s">%s</a>
                  </p>
                </div>
                """.formatted(link, link, link);

        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, "utf-8");
            helper.setFrom(fromAddress);
            helper.setTo(toEmail);
            helper.setSubject("Verify your email address");
            helper.setText(html, true);
            mailSender.send(message);
        } catch (Exception e) {
            log.error("Failed to send verification email to {}: {}", toEmail, e.getMessage());
        }
    }

    @Async
    public void sendPasswordResetEmail(String toEmail, String token) {
        String link = frontendUrl + "/reset-password?token=" + token;
        String html = """
                <div style="font-family:sans-serif;max-width:480px;margin:auto">
                  <h2>Reset your password</h2>
                  <p>Click the button below to set a new password. The link expires in 60 minutes.</p>
                  <a href="%s" style="display:inline-block;padding:12px 24px;background:#000;color:#fff;
                     text-decoration:none;border-radius:6px;font-weight:bold">Reset password</a>
                  <p style="margin-top:16px;color:#666;font-size:13px">
                    Or copy this link:<br><a href="%s">%s</a>
                  </p>
                  <p style="color:#666;font-size:13px">If you did not request a password reset, you can ignore this email.</p>
                </div>
                """.formatted(link, link, link);

        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, "utf-8");
            helper.setFrom(fromAddress);
            helper.setTo(toEmail);
            helper.setSubject("Reset your password");
            helper.setText(html, true);
            mailSender.send(message);
        } catch (Exception e) {
            log.error("Failed to send password reset email to {}: {}", toEmail, e.getMessage());
        }
    }
}

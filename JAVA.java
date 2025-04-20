// ======= MAIN APPLICATION CLASS =======
package com.certverify.app;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class CertificateVerificationSystemApplication {
    public static void main(String[] args) {
        SpringApplication.run(CertificateVerificationSystemApplication.class, args);
    }
}

// ======= MODELS =======
package com.certverify.app.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "certificates")
public class Certificate {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false)
    private String recipientName;

    @Column(nullable = false)
    private String recipientEmail;

    @Column(nullable = false)
    private String certificateTitle;

    @Column(nullable = false)
    private String issuingOrganization;

    @Column(nullable = false)
    private LocalDateTime issueDate;

    private LocalDateTime expiryDate;

    @Column(nullable = false)
    private String certificateHash;

    @Column(nullable = false)
    private String digitalSignature;

    @ManyToOne
    @JoinColumn(name = "issuer_id", nullable = false)
    private User issuer;

    private boolean revoked = false;

    // Getters and Setters
    public UUID getId() { return id; }
    public void setId(UUID id) { this.id = id; }

    public String getRecipientName() { return recipientName; }
    public void setRecipientName(String recipientName) { this.recipientName = recipientName; }

    public String getRecipientEmail() { return recipientEmail; }
    public void setRecipientEmail(String recipientEmail) { this.recipientEmail = recipientEmail; }

    public String getCertificateTitle() { return certificateTitle; }
    public void setCertificateTitle(String certificateTitle) { this.certificateTitle = certificateTitle; }

    public String getIssuingOrganization() { return issuingOrganization; }
    public void setIssuingOrganization(String issuingOrganization) { this.issuingOrganization = issuingOrganization; }

    public LocalDateTime getIssueDate() { return issueDate; }
    public void setIssueDate(LocalDateTime issueDate) { this.issueDate = issueDate; }

    public LocalDateTime getExpiryDate() { return expiryDate; }
    public void setExpiryDate(LocalDateTime expiryDate) { this.expiryDate = expiryDate; }

    public String getCertificateHash() { return certificateHash; }
    public void setCertificateHash(String certificateHash) { this.certificateHash = certificateHash; }

    public String getDigitalSignature() { return digitalSignature; }
    public void setDigitalSignature(String digitalSignature) { this.digitalSignature = digitalSignature; }

    public User getIssuer() { return issuer; }
    public void setIssuer(User issuer) { this.issuer = issuer; }

    public boolean isRevoked() { return revoked; }
    public void setRevoked(boolean revoked) { this.revoked = revoked; }
}

package com.certverify.app.model;

import jakarta.persistence.*;
import java.util.Set;
import java.util.HashSet;

@Entity
@Table(name = "users")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String username;

    @Column(nullable = false)
    private String password;

    @Column(nullable = false, unique = true)
    private String email;

    @Column(nullable = false)
    private String organizationName;

    @Column(nullable = false)
    private String publicKey;

    @Column(nullable = false)
    private String privateKey;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "user_roles", joinColumns = @JoinColumn(name = "user_id"))
    @Column(name = "role")
    private Set<String> roles = new HashSet<>();

    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }

    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }

    public String getOrganizationName() { return organizationName; }
    public void setOrganizationName(String organizationName) { this.organizationName = organizationName; }

    public String getPublicKey() { return publicKey; }
    public void setPublicKey(String publicKey) { this.publicKey = publicKey; }

    public String getPrivateKey() { return privateKey; }
    public void setPrivateKey(String privateKey) { this.privateKey = privateKey; }

    public Set<String> getRoles() { return roles; }
    public void setRoles(Set<String> roles) { this.roles = roles; }
}

package com.certverify.app.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "verification_logs")
public class VerificationLog {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private UUID certificateId;

    @Column(nullable = false)
    private String verifierIp;

    private String verifierEmail;

    @Column(nullable = false)
    private LocalDateTime verificationTime;

    @Column(nullable = false)
    private boolean verificationResult;

    private String failureReason;

    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public UUID getCertificateId() { return certificateId; }
    public void setCertificateId(UUID certificateId) { this.certificateId = certificateId; }

    public String getVerifierIp() { return verifierIp; }
    public void setVerifierIp(String verifierIp) { this.verifierIp = verifierIp; }

    public String getVerifierEmail() { return verifierEmail; }
    public void setVerifierEmail(String verifierEmail) { this.verifierEmail = verifierEmail; }

    public LocalDateTime getVerificationTime() { return verificationTime; }
    public void setVerificationTime(LocalDateTime verificationTime) { this.verificationTime = verificationTime; }

    public boolean isVerificationResult() { return verificationResult; }
    public void setVerificationResult(boolean verificationResult) { this.verificationResult = verificationResult; }

    public String getFailureReason() { return failureReason; }
    public void setFailureReason(String failureReason) { this.failureReason = failureReason; }
}

// ======= REPOSITORIES =======
package com.certverify.app.repository;

import com.certverify.app.model.Certificate;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;
import java.util.UUID;
import java.util.List;

public interface CertificateRepository extends JpaRepository<Certificate, UUID> {
    List<Certificate> findByIssuerId(Long issuerId);
    List<Certificate> findByRecipientEmail(String recipientEmail);
    Optional<Certificate> findByIdAndRevoked(UUID id, boolean revoked);
}

package com.certverify.app.repository;

import com.certverify.app.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
    Optional<User> findByEmail(String email);
    boolean existsByUsername(String username);
    boolean existsByEmail(String email);
}

package com.certverify.app.repository;

import com.certverify.app.model.VerificationLog;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;
import java.util.UUID;

public interface VerificationLogRepository extends JpaRepository<VerificationLog, Long> {
    List<VerificationLog> findByCertificateId(UUID certificateId);
}

// ======= DTOs =======
package com.certverify.app.dto;

import java.time.LocalDateTime;

public class CertificateRequest {
    private String recipientName;
    private String recipientEmail;
    private String certificateTitle;
    private LocalDateTime expiryDate;
    private String additionalDetails;

    // Getters and Setters
    public String getRecipientName() { return recipientName; }
    public void setRecipientName(String recipientName) { this.recipientName = recipientName; }

    public String getRecipientEmail() { return recipientEmail; }
    public void setRecipientEmail(String recipientEmail) { this.recipientEmail = recipientEmail; }

    public String getCertificateTitle() { return certificateTitle; }
    public void setCertificateTitle(String certificateTitle) { this.certificateTitle = certificateTitle; }

    public LocalDateTime getExpiryDate() { return expiryDate; }
    public void setExpiryDate(LocalDateTime expiryDate) { this.expiryDate = expiryDate; }

    public String getAdditionalDetails() { return additionalDetails; }
    public void setAdditionalDetails(String additionalDetails) { this.additionalDetails = additionalDetails; }
}

package com.certverify.app.dto;

import java.time.LocalDateTime;
import java.util.UUID;

public class CertificateResponse {
    private UUID id;
    private String recipientName;
    private String recipientEmail;
    private String certificateTitle;
    private String issuingOrganization;
    private LocalDateTime issueDate;
    private LocalDateTime expiryDate;
    private String qrCodeUrl;
    private boolean valid;

    // Getters and Setters
    public UUID getId() { return id; }
    public void setId(UUID id) { this.id = id; }

    public String getRecipientName() { return recipientName; }
    public void setRecipientName(String recipientName) { this.recipientName = recipientName; }

    public String getRecipientEmail() { return recipientEmail; }
    public void setRecipientEmail(String recipientEmail) { this.recipientEmail = recipientEmail; }

    public String getCertificateTitle() { return certificateTitle; }
    public void setCertificateTitle(String certificateTitle) { this.certificateTitle = certificateTitle; }

    public String getIssuingOrganization() { return issuingOrganization; }
    public void setIssuingOrganization(String issuingOrganization) { this.issuingOrganization = issuingOrganization; }

    public LocalDateTime getIssueDate() { return issueDate; }
    public void setIssueDate(LocalDateTime issueDate) { this.issueDate = issueDate; }

    public LocalDateTime getExpiryDate() { return expiryDate; }
    public void setExpiryDate(LocalDateTime expiryDate) { this.expiryDate = expiryDate; }

    public String getQrCodeUrl() { return qrCodeUrl; }
    public void setQrCodeUrl(String qrCodeUrl) { this.qrCodeUrl = qrCodeUrl; }

    public boolean isValid() { return valid; }
    public void setValid(boolean valid) { this.valid = valid; }
}

package com.certverify.app.dto;

public class VerificationRequest {
    private String certificateId;
    private String verifierEmail;

    // Getters and Setters
    public String getCertificateId() { return certificateId; }
    public void setCertificateId(String certificateId) { this.certificateId = certificateId; }

    public String getVerifierEmail() { return verifierEmail; }
    public void setVerifierEmail(String verifierEmail) { this.verifierEmail = verifierEmail; }
}

package com.certverify.app.dto;

import java.time.LocalDateTime;

public class VerificationResponse {
    private boolean valid;
    private String recipientName;
    private String certificateTitle;
    private String issuingOrganization;
    private LocalDateTime issueDate;
    private LocalDateTime expiryDate;
    private String message;

    // Getters and Setters
    public boolean isValid() { return valid; }
    public void setValid(boolean valid) { this.valid = valid; }

    public String getRecipientName() { return recipientName; }
    public void setRecipientName(String recipientName) { this.recipientName = recipientName; }

    public String getCertificateTitle() { return certificateTitle; }
    public void setCertificateTitle(String certificateTitle) { this.certificateTitle = certificateTitle; }

    public String getIssuingOrganization() { return issuingOrganization; }
    public void setIssuingOrganization(String issuingOrganization) { this.issuingOrganization = issuingOrganization; }

    public LocalDateTime getIssueDate() { return issueDate; }
    public void setIssueDate(LocalDateTime issueDate) { this.issueDate = issueDate; }

    public LocalDateTime getExpiryDate() { return expiryDate; }
    public void setExpiryDate(LocalDateTime expiryDate) { this.expiryDate = expiryDate; }

    public String getMessage() { return message; }
    public void setMessage(String message) { this.message = message; }
}

// ======= SERVICES =======
package com.certverify.app.service;

import com.certverify.app.dto.CertificateRequest;
import com.certverify.app.dto.CertificateResponse;
import com.certverify.app.model.Certificate;
import com.certverify.app.model.User;
import com.certverify.app.repository.CertificateRepository;
import com.certverify.app.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
public class CertificateService {

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private CryptographyService cryptographyService;

    @Autowired
    private QRCodeService qrCodeService;

    public CertificateResponse issueCertificate(CertificateRequest request) {
        UserDetails userDetails = (UserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        Optional<User> userOptional = userRepository.findByUsername(userDetails.getUsername());
        
        if (userOptional.isEmpty()) {
            throw new RuntimeException("User not found");
        }
        
        User issuer = userOptional.get();
        Certificate certificate = new Certificate();
        certificate.setRecipientName(request.getRecipientName());
        certificate.setRecipientEmail(request.getRecipientEmail());
        certificate.setCertificateTitle(request.getCertificateTitle());
        certificate.setIssuingOrganization(issuer.getOrganizationName());
        certificate.setIssueDate(LocalDateTime.now());
        certificate.setExpiryDate(request.getExpiryDate());
        certificate.setIssuer(issuer);
        
        // Create certificate hash and digital signature
        String certificateData = certificate.getRecipientName() + certificate.getRecipientEmail() + 
                                certificate.getCertificateTitle() + certificate.getIssuingOrganization() + 
                                certificate.getIssueDate().toString();
        
        if (certificate.getExpiryDate() != null) {
            certificateData += certificate.getExpiryDate().toString();
        }
        
        String certificateHash = cryptographyService.generateSHA256Hash(certificateData);
        certificate.setCertificateHash(certificateHash);
        
        String digitalSignature = cryptographyService.sign(certificateHash, issuer.getPrivateKey());
        certificate.setDigitalSignature(digitalSignature);
        
        Certificate savedCertificate = certificateRepository.save(certificate);
        
        return convertToResponse(savedCertificate);
    }
    
    public List<CertificateResponse> getCertificatesForCurrentUser() {
        UserDetails userDetails = (UserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        Optional<User> userOptional = userRepository.findByUsername(userDetails.getUsername());
        
        if (userOptional.isEmpty()) {
            throw new RuntimeException("User not found");
        }
        
        List<Certificate> certificates = certificateRepository.findByIssuerId(userOptional.get().getId());
        return certificates.stream()
            .map(this::convertToResponse)
            .collect(Collectors.toList());
    }
    
    public boolean revokeCertificate(UUID certificateId) {
        Optional<Certificate> certificateOptional = certificateRepository.findById(certificateId);
        
        if (certificateOptional.isEmpty()) {
            return false;
        }
        
        Certificate certificate = certificateOptional.get();
        certificate.setRevoked(true);
        certificateRepository.save(certificate);
        return true;
    }
    
    private CertificateResponse convertToResponse(Certificate certificate) {
        CertificateResponse response = new CertificateResponse();
        response.setId(certificate.getId());
        response.setRecipientName(certificate.getRecipientName());
        response.setRecipientEmail(certificate.getRecipientEmail());
        response.setCertificateTitle(certificate.getCertificateTitle());
        response.setIssuingOrganization(certificate.getIssuingOrganization());
        response.setIssueDate(certificate.getIssueDate());
        response.setExpiryDate(certificate.getExpiryDate());
        response.setValid(!certificate.isRevoked() && (certificate.getExpiryDate() == null || certificate.getExpiryDate().isAfter(LocalDateTime.now())));
        
        // Generate QR code URL
        String qrCodeUrl = qrCodeService.generateQRCodeUrl(certificate.getId().toString());
        response.setQrCodeUrl(qrCodeUrl);
        
        return response;
    }
}

package com.certverify.app.service;

import org.springframework.stereotype.Service;
import java.security.*;
import java.util.Base64;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;

@Service
public class CryptographyService {

    public Map<String, String> generateKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();
        
        String privateKey = Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded());
        String publicKey = Base64.getEncoder().encodeToString(pair.getPublic().getEncoded());
        
        Map<String, String> keyPair = new HashMap<>();
        keyPair.put("privateKey", privateKey);
        keyPair.put("publicKey", publicKey);
        
        return keyPair;
    }
    
    public String sign(String data, String privateKeyString) {
        try {
            byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyString);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
            
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(data.getBytes(StandardCharsets.UTF_8));
            
            return Base64.getEncoder().encodeToString(signature.sign());
        } catch (Exception e) {
            throw new RuntimeException("Error signing data: " + e.getMessage(), e);
        }
    }
    
    public boolean verify(String data, String signature, String publicKeyString) {
        try {
            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyString);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = keyFactory.generatePublic(keySpec);
            
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initVerify(publicKey);
            sig.update(data.getBytes(StandardCharsets.UTF_8));
            
            return sig.verify(Base64.getDecoder().decode(signature));
        } catch (Exception e) {
            throw new RuntimeException("Error verifying signature: " + e.getMessage(), e);
        }
    }
    
    public String generateSHA256Hash(String data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(data.getBytes(StandardCharsets.UTF_8));
            
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            throw new RuntimeException("Error generating hash: " + e.getMessage(), e);
        }
    }
}

package com.certverify.app.service;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Base64;

@Service
public class QRCodeService {

    @Value("${app.verification.url}")
    private String verificationBaseUrl;

    public String generateQRCodeUrl(String certificateId) {
        return verificationBaseUrl + "?id=" + certificateId;
    }

    public String generateQRCodeImage(String certificateId) {
        try {
            String verificationUrl = generateQRCodeUrl(certificateId);
            
            QRCodeWriter qrCodeWriter = new QRCodeWriter();
            BitMatrix bitMatrix = qrCodeWriter.encode(verificationUrl, BarcodeFormat.QR_CODE, 250, 250);
            
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            MatrixToImageWriter.writeToStream(bitMatrix, "PNG", outputStream);
            
            return "data:image/png;base64," + Base64.getEncoder().encodeToString(outputStream.toByteArray());
        } catch (WriterException | IOException e) {
            throw new RuntimeException("Error generating QR code: " + e.getMessage(), e);
        }
    }
}

package com.certverify.app.service;

import com.certverify.app.dto.VerificationRequest;
import com.certverify.app.dto.VerificationResponse;
import com.certverify.app.model.Certificate;
import com.certverify.app.model.User;
import com.certverify.app.model.VerificationLog;
import com.certverify.app.repository.CertificateRepository;
import com.certverify.app.repository.VerificationLogRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Service
public class VerificationService {

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private VerificationLogRepository verificationLogRepository;

    @Autowired
    private CryptographyService cryptographyService;

    public VerificationResponse verifyCertificate(VerificationRequest request, HttpServletRequest httpRequest) {
        VerificationResponse response = new VerificationResponse();
        UUID certificateId;
        try {
            certificateId = UUID.fromString(request.getCertificateId());
        } catch (IllegalArgumentException e) {
            response.setValid(false);
            response.setMessage("Invalid certificate ID format");
            logVerification(request.getCertificateId(), httpRequest.getRemoteAddr(), request.getVerifierEmail(), false, "Invalid certificate ID format");
            return response;
        }
        
        Optional<Certificate> certificateOptional = certificateRepository.findById(certificateId);
        
        if (certificateOptional.isEmpty()) {
            response.setValid(false);
            response.setMessage("Certificate not found");
            logVerification(certificateId, httpRequest.getRemoteAddr(), request.getVerifierEmail(), false, "Certificate not found");
            return response;
        }
        
        Certificate certificate = certificateOptional.get();
        
        // Check if certificate is revoked
        if (certificate.isRevoked()) {
            response.setValid(false);
            response.setMessage("Certificate has been revoked");
            logVerification(certificateId, httpRequest.getRemoteAddr(), request.getVerifierEmail(), false, "Certificate revoked");
            return response;
        }
        
        // Check if certificate is expired
        if (certificate.getExpiryDate() != null && certificate.getExpiryDate().isBefore(LocalDateTime.now())) {
            response.setValid(false);
            response.setMessage("Certificate has expired");
            logVerification(certificateId, httpRequest.getRemoteAddr(), request.getVerifierEmail(), false, "Certificate expired");
            return response;
        }
        
        // Verify digital signature
        String certificateData = certificate.getRecipientName() + certificate.getRecipientEmail() + 
                               certificate.getCertificateTitle() + certificate.getIssuingOrganization() + 
                               certificate.getIssueDate().toString();
        
        if (certificate.getExpiryDate() != null) {
            certificateData += certificate.getExpiryDate().toString();
        }
        
        String calculatedHash = cryptographyService.generateSHA256Hash(certificateData);
        User issuer = certificate.getIssuer();
        
        if (!calculatedHash.equals(certificate.getCertificateHash())) {
            response.setValid(false);
            response.setMessage("Certificate hash mismatch");
            logVerification(certificateId, httpRequest.getRemoteAddr(), request.getVerifierEmail(), false, "Hash mismatch");
            return response;
        }
        
        boolean validSignature = cryptographyService.verify(
            calculatedHash, 
            certificate.getDigitalSignature(), 
            issuer.getPublicKey()
        );
        
        if (!validSignature) {
            response.setValid(false);
            response.setMessage("Invalid digital signature");
            logVerification(certificateId, httpRequest.getRemoteAddr(), request.getVerifierEmail(), false, "Invalid signature");
            return response;
        }
        
        // All verification passed, certificate is valid
        response.setValid(true);
        response.setRecipientName(certificate.getRecipientName());
        response.setCertificateTitle(certificate.getCertificateTitle());
        response.setIssuingOrganization(certificate.getIssuingOrganization());
        response.setIssueDate(certificate.getIssueDate());
        response.setExpiryDate(certificate.getExpiryDate());
        response.setMessage("Certificate is valid");
        
        logVerification(certificateId, httpRequest.getRemoteAddr(), request.getVerifierEmail(), true, null);
        
        return response;
    }
    
    private void logVerification(UUID certificateId, String verifierIp, String verifierEmail, boolean result, String failureReason) {
        VerificationLog log = new VerificationLog();
        log.setCertificateId(certificateId);
        log.setVerifierIp(verifierIp);
        log.setVerifierEmail(verifierEmail);
        log.setVerificationTime(LocalDateTime.now());
        log.setVerificationResult(result);
        log.setFailureReason(failureReason);
        
        verificationLogRepository.save(log);
    }
    
    private void logVerification(String certificateIdStr, String verifierIp, String verifierEmail, boolean result, String failureReason) {
        try {
            UUID certificateId = UUID.fromString(certificateIdStr);
            logVerification(certificateId, verifierIp, verifierEmail, result, failureReason);
        } catch (IllegalArgumentException e) {
            // Log with null certificate ID if the string couldn't be parsed
            VerificationLog log = new VerificationLog();
            log.setVerifierIp(verifierIp);
            log.setVerifierEmail(verifierEmail);
            log.setVerificationTime(LocalDateTime.now());
            log.setVerificationResult(result);
            log.setFailureReason(failureReason);
            
            verificationLogRepository.save(log);
        }
    }
}

// ======= CONTROLLERS =======
package com.certverify.app.controller;

import com.certverify.app.dto.CertificateRequest;
import com.certverify.app.dto.CertificateResponse;
import com.certverify.app.service.CertificateService;
import com.certverify.app.service.QRCodeService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/certificates")
public class CertificateController {

    @Autowired
    private CertificateService certificateService;
    
    @Autowired
    private QRCodeService qrCodeService;

    @PostMapping
    @PreAuthorize("hasRole('ISSUER')")
    public ResponseEntity<CertificateResponse> issueCertificate(@RequestBody CertificateRequest request) {
        CertificateResponse response = certificateService.issueCertificate(request);
        return ResponseEntity
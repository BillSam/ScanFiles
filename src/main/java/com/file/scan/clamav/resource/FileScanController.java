package com.file.scan.clamav.resource;

import org.springframework.http.ResponseEntity;
import com.file.scan.clamav.service.FileScanService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import com.cloudmersive.client.ScanApi;
import com.cloudmersive.client.invoker.ApiClient;
import com.cloudmersive.client.invoker.ApiException;
import com.cloudmersive.client.invoker.auth.ApiKeyAuth;
import com.cloudmersive.client.model.VirusScanResult;
import com.file.scan.clamav.dto.*;

import java.io.File;
import java.util.List;
import org.springframework.http.HttpStatus;


import com.cloudmersive.client.invoker.Configuration;


@CrossOrigin
@RestController
@RequestMapping("/api/v1/scan")
public class FileScanController {

  private static Logger LOGGER = LoggerFactory.getLogger(FileScanController.class);

  @Autowired
  private FileScanService fileScanService;

    @PostMapping("/clamav")
    public ResponseDto<List<FileScanResponseDto>> uploadFiles(@RequestParam("files") MultipartFile files) {
        return new ResponseDto<List<FileScanResponseDto>>(fileScanService.scanFiles(new MultipartFile[] {files}));
    }


    @PostMapping("/cloudsource")
    public ResponseEntity<String> scanFile(@RequestParam("files") MultipartFile file) {
        try {
           // Convert the MultipartFile to a File
            File convertedFile = fileScanService.convertMultipartFileToFile(file);

            // Perform the virus scan using the converted file
            ApiClient defaultClient = Configuration.getDefaultApiClient();

            // Configure API key authorization: Apikey
            ApiKeyAuth apiKey = (ApiKeyAuth) defaultClient.getAuthentication("Apikey");
            apiKey.setApiKey("25672c80-cf44-4fd8-ba2f-2d31fb5ae55c");

            ScanApi apiInstance = new ScanApi();

            try {
                VirusScanResult result = apiInstance.scanFile(convertedFile);
                System.out.println(result);
                if (result.isCleanResult()) {
                  return ResponseEntity.ok("File scanned successfully. Clean result.");
              } else {
                  return ResponseEntity.ok("File contains viruses. Found viruses: " + result.getFoundViruses());
              }
                // Return a response (e.g., success message or scan result)
                // return ResponseEntity.ok(result);
            } catch (ApiException e) {
                System.err.println("Exception when calling ScanAPI#scanFile");
                e.printStackTrace();
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error scanning the file");
            }
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error converting and scanning the file");
        }
    }
}



package com.SpringSecurity.project.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/management")
@RequiredArgsConstructor
@PreAuthorize("hasRole('MANAGER')")
public class ManagementController {

    @GetMapping
    @PreAuthorize("hasAuthority('management:read')")
    public String get(){
        return "GET::management controller";
    }

    @PreAuthorize("hasAuthority('management:create')")
    @PostMapping
    public String post(){
        return "POST::management controller";
    }


    @PreAuthorize("hasAuthority('management:update')")
    @PutMapping
    public String put(){
        return "PUT::admin controller";
    }

    @PreAuthorize("hasAuthority('management:delete')")
    @DeleteMapping
    public String delete(){
        return "DELETE::admin controller";
    }


}

package com.example.jwt.refresh.study.jwt.auth.domain.model;

import com.example.jwt.refresh.study.jwt.auth.role.ERole;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.*;

@Entity
@Table(name = "tb_role")
@NoArgsConstructor
@Getter
public class Role {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    @Enumerated(EnumType.STRING)
    private ERole role;

    @Builder
    public Role(ERole role) {
        this.role = role;
    }
}

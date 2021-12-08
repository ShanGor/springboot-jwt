package cn.gzten.jwt.domain;

import lombok.Data;

import javax.persistence.*;

/**
 * Created by nydiarra on 06/05/17.
 */
@Entity
@Table(name="app_role")
@Data
public class Role {
    public static final String ROLE_ADMIN = "ADMIN_USER";
    public static final String ROLE_STD = "STANDARD_USER";

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name="role_name")
    private String roleName;

    @Column(name="description")
    private String description;
}

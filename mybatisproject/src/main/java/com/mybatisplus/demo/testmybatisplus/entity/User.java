package com.mybatisplus.demo.testmybatisplus.entity;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.experimental.Accessors;

/**
 * <p>
 * 
 * </p>
 *
 * @author jobob
 * @since 2019-09-03
 */
@Data
@Accessors(chain = true)
public class User{

    private static final long serialVersionUID = 1L;


    private Integer id;
    /**
     * 姓名
     */
    private String name;

    /**
     * 年龄
     */
    private Integer age;

    /**
     * 邮箱
     */
    private String email;


}

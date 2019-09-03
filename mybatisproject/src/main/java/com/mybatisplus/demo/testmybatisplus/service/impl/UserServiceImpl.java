package com.mybatisplus.demo.testmybatisplus.service.impl;

import com.mybatisplus.demo.testmybatisplus.entity.User;
import com.mybatisplus.demo.testmybatisplus.mapper.UserMapper;
import com.mybatisplus.demo.testmybatisplus.service.IUserService;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import org.springframework.stereotype.Service;

/**
 * <p>
 *  服务实现类
 * </p>
 *
 * @author jobob
 * @since 2019-09-03
 */
@Service
public class UserServiceImpl extends ServiceImpl<UserMapper, User> implements IUserService {

}

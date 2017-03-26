/**
 * @author zhixin wen <wenzhixin2010@gmail.com>
 * @version 1.0.0
 * @github https://github.com/wenzhixin/bootstrap-login
 * @blog http://wenzhixin.net.cn
 */

(function ($) {

    'use strict';

    function Login($el, options) {
        this.$el = $el;
        this.options = options;
        if (this.options.type === 'dropdown') {
            this.$el.addClass('dropdown');
        }
    }

    Login.prototype = {
        constructor: Login,

        init: function () {
            this.$el.html(Login.getTemplate(this.options));
            this.$form = this.$el.find('form');
            this.$username = this.$el.find('input[name="username"]');
            this.$password = this.$el.find('input[name="password"]');
            this.$error = this.$el.find('.alert-error');
            this.events();
        },

        events: function () {
            var that = this;
            this.$form.submit(function () {
                var locale = Login.locale[that.options.lang],
                    username = $.trim(that.$username.val()),
                    password = that.$password.val();

                if (!that.validate(username, password)) {
                    return false;
                }
                if (that.options.action === '') {
                    var showResult = function (result) {
                            if (typeof result === 'undefined' || result) {
                                that.$error.hide();
                            } else {
                                that.$error.show().find('span').html(locale.error_login);
                            }
                        },
                        result = that.options.onSubmit(username, password, function (result) {
                            showResult(result);
                        });
                    showResult(result);
                    return false;
                }
            });
            this.$error.find('button').click(function () {
                that.$error.hide();
            });
        },

        validate: function (username, password) {
            var locale = Login.locale[this.options.lang];
            if (username === '') {
                this.$error.show().find('span').html(locale.error_input + locale.username_tip);
                this.$username.focus();
                return false;
            }
            if (password === '') {
                this.$error.show().find('span').html(locale.error_input + locale.password_tip);
                this.$password.focus();
                return false;
            }
            return true;
        }
    };

    Login.locale = {
        'zh_CN': {
            title: '登录 ',
            username_tip: '用户名',
            password_tip: '密码',
            sign_in: '登录',
            error_input: '<strong>错误！</strong> 请输入您的',
            error_login: '<strong>错误！</strong> 您输入的用户名或者密码错误。'
        },
        'en': {
            title: 'Sign in to ',
            username_tip: 'Username',
            password_tip: 'Password',
            sign_in: 'Sign in',
            error_input: '<strong>Error!</strong> Please enter your ',
            error_login: '<strong>Error!</strong> The username or password you enter is incorrect.'
        }
    };

    Login.getTemplate = function (options) {
        var locale = Login.locale[options.lang], templates = {
            normal: [
                '<div class="bs-login">',
                '<div class="bs-signin">',
                '<h1>' + locale.title + options.title + '</h1>',
                '<form action="' + options.action + '" method="POST">',
                '<fieldset>',
                '<div class="clearfix holding">',
                '<input class="form-control input-xlarge" type="text" name="username" autocomplete="on" ',
                'placeholder="' + locale.username_tip + '">',
                '</div>',
                '<div class="clearfix holding">',
                '<input class="form-control input-xlarge" type="password" name="password" ',
                'placeholder="' + locale.password_tip + '">',
                '</div>',
                '</fieldset>',
                '<div class="alert alert-error alert-danger">',
                '<button type="button" class="close">&times;</button>',
                '<span></span>',
                '</div>',
                '<div class="form-horizontal normal-button">',
                '<input type="submit" class="btn btn-primary" value="' + locale.sign_in + '" />',
                '</div>',
                '</form>',
                '</div>',
                '</div>'].join(''),
            dropdown: [
                '<a href="javascript:void(0)" class="dropdown-toggle" data-toggle="dropdown">',
                locale.title + options.title + ' <b class="caret"></b>',
                '</a>',
                '<ul class="bs-dropdown-login dropdown-menu">',
                '<li>',
                '<form>',
                '<fieldset>',
                '<label>' + locale.username_tip + '</label>',
                '<input class="form-control input-large" name="username" type="text">',
                '<label>' + locale.password_tip + '</label>',
                '<input class="form-control input-large" name="password" type="password">',
                '<div class="alert alert-error alert-danger">',
                '<button type="button" class="close">&times;</button>',
                '<span></span>',
                '</div>',
                '<div class="dropdown-button pull-right">',
                '<button type="submit" class="btn btn-default">',
                locale.sign_in,
                '</button>',
                '</div>',
                '</fieldset>',
                '</form>',
                '</li>',
                '</ul>'].join('')
        };
        if (!templates.hasOwnProperty(options.type)) {
            options.type = 'normal';
        }
        return templates[options.type];
    };

    $.fn.bootstrapLogin = function () {
        var option = arguments[0],
            args = arguments,

            value,
            allowedMethods = [];

        this.each(function () {
            var $this = $(this),
                data = $this.data('bootstrapLogin'),
                options = $.extend({}, $.fn.bootstrapLogin.defaults, $this.data(),
                    typeof option === 'object' && option);

            if (!data) {
                data = new Login($this, options);
                $this.data('bootstrapLogin', data);
            }

            if (typeof option === 'string') {
                if ($.inArray(option, allowedMethods) < 0) {
                    throw "Unknown method: " + option;
                }
                value = data[option](args[1]);
            } else {
                data.init();
            }
        });

        return value ? value : this;
    };

    $.fn.bootstrapLogin.defaults = {
        lang: 'zh_CN', //'zh_CN' or 'en'
        title: '后台',
        type: 'normal', //'normal' or 'dropdown'
        action: '',
        onSubmit: function () {
            return false;
        }
    };

    $(function () {
        $('[data-toggle="login"]').bootstrapLogin();
    });
})(jQuery);

# name: discourse-email-token
# about: Adds an endpoint to allow admins to retrieve an email token for any user
# version: 0.1
# authors: Angus McLeod
# url: https://github.com/paviliondev/discourse-email-token

after_initialize do
  Discourse::Application.routes.append do
    post "/users/email-login-token" => "users#email_login_token", constraints: { format: 'json' }
    get "/session/email-login-topic/:token/:topic_id" => "session#email_login_topic"
    get "/session/email-login-composer/:token" => "session#email_login_topic"
  end
  
  require_dependency 'users_controller'
  class ::UsersController    
    def email_login_token
      ensure_admin
      raise Discourse::InvalidAccess if !is_api?
      raise Discourse::NotFound if !SiteSetting.enable_local_logins_via_email
      
      expires_now
      params.require(:login)

      RateLimiter.new(nil, "email-login-hour-#{request.remote_ip}", SiteSetting.email_login_token_hour_limit, 1.hour).performed!
      RateLimiter.new(nil, "email-login-min-#{request.remote_ip}", SiteSetting.email_login_token_minute_limit, 1.minute).performed!
      user = User.human_users.find_by_username_or_email(params[:login])
      user_presence = user.present? && !user.staged
      
      json = success_json

      if user
        RateLimiter.new(nil, "email-login-hour-#{user.id}", SiteSetting.email_login_token_hour_limit, 1.hour).performed!
        RateLimiter.new(nil, "email-login-min-#{user.id}", SiteSetting.email_login_token_minute_limit, 1.minute).performed!

        if user_presence
          email_token = user.email_tokens.create!(email: user.email)

          json[:token] = email_token
        end
      end

      json[:user_found] = user_presence unless SiteSetting.hide_email_address_taken
      
      render json: json
    rescue RateLimiter::LimitExceeded
      render_json_error(I18n.t("rate_limiter.slow_down"))
    end
  end
  
  require_dependency 'session_controller'
  class ::SessionController
    skip_before_action :preload_json, :check_xhr, only: %i(email_login_topic)

    def email_login_topic
      raise Discourse::NotFound if !SiteSetting.enable_local_logins_via_email
      second_factor_token = params[:second_factor_token]
      second_factor_method = params[:second_factor_method].to_i
      token = params[:token]
      matched_token = EmailToken.confirmable(token)

      if matched_token&.user&.totp_enabled?
        if !second_factor_token.present?
          return render json: { error: I18n.t('login.invalid_second_factor_code') }
        elsif !matched_token.user.authenticate_second_factor(second_factor_token, second_factor_method)
          RateLimiter.new(nil, "second-factor-min-#{request.remote_ip}", SiteSetting.email_login_token_minute_limit, 1.minute).performed!
          return render json: { error: I18n.t('login.invalid_second_factor_code') }
        end
      end

      if user = EmailToken.confirm(token)
        if login_not_approved_for?(user)
          return render json: login_not_approved
        elsif payload = login_error_check(user)
          return render json: payload
        else
          log_on_user(user)
          
          redirect = "/"
          
          if params[:topic_id] && (topic = Topic.find(params[:topic_id]))
            redirect = topic.relative_url if topic
          elsif params[:title] || params[:body]
            redirect = "/new-topic?"
            first = true
            
            ["title", "body", "category", "tags"].each do |p|
              if value = params[p.to_sym]
                redirect += "&" if !first
                redirect += "#{p}=#{CGI.escape(value)}"
                first = false if first
              end
            end
          end
          
          return redirect_to path(redirect)
        end
      end

      return render json: { error: I18n.t('email_login.invalid_token') }
    end
  end
end
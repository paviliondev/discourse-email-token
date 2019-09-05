# name: discourse-email-token
# about: Adds an endpoint to allow admins to retrieve an email token for any user
# version: 0.1
# authors: Angus McLeod
# url: https://github.com/paviliondev/discourse-email-token

after_initialize do
  Discourse::Application.routes.append do
    post "/users/email-login-token" => "users#email_login_token", constraints: { format: 'json' }
  end
  
  require_dependency 'users_controller'
  class ::UsersController    
    def email_login_token
      ensure_admin
      raise Discourse::InvalidAccess if !is_api?
      raise Discourse::NotFound if !SiteSetting.enable_local_logins_via_email
      
      expires_now
      params.require(:login)

      RateLimiter.new(nil, "email-login-hour-#{request.remote_ip}", 6, 1.hour).performed!
      RateLimiter.new(nil, "email-login-min-#{request.remote_ip}", 3, 1.minute).performed!
      user = User.human_users.find_by_username_or_email(params[:login])
      user_presence = user.present? && !user.staged
      
      json = success_json

      if user
        RateLimiter.new(nil, "email-login-hour-#{user.id}", 6, 1.hour).performed!
        RateLimiter.new(nil, "email-login-min-#{user.id}", 3, 1.minute).performed!

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
end
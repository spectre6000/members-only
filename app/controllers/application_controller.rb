class ApplicationController < ActionController::Base
  # Prevent CSRF attacks by raising an exception.
  # For APIs, you may want to use :null_session instead.
  protect_from_forgery with: :exception
  
  def log_in(user)
    remember_token = user.generate_token
    cookies.permanent.signed[:remember_token] = remember_token
    user.update_attribute(:remember_token, remember_token)
    current_user
  end

  def current_user
    @current_user ||= User.find_by(remember_token: cookies.signed[:remember_digest])
  end

  def log_out
    @current_user = nil
    cookies.signed[:remember_token] = nil
  end

end
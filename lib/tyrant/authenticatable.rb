require "disposable/twin/struct"

module Tyrant
  # Encapsulates authentication management logic for a particular user.
  class Authenticatable < Disposable::Twin
    feature Default
    feature Sync # FIXME: really?

    property :confirmation_token
    property :confirmed_at
    property :confirmation_sent_at
    property :encrypted_password
    property :password_salt
    property :remember_token

    module Confirm
      def confirmable!
        confirmation_token = SecureRandom.urlsafe_base64
        confirmation_created_at = DateTime.now
        self
      end

      # without token, this decides whether the user model can be activated (e.g. via "set a password").
      # with token, this additionally tests if the token is correct.
      def confirmable?(token=false)
        persisted_token = confirmation_token

        # TODO: add expiry etc.
        return false unless (persisted_token.is_a?(String) and persisted_token.size > 0)

        return compare_token(token) unless token==false
        true
      end

      # alias_method :confirmed?, :confirmable?
      def confirmed?
        not confirmed_at.nil?
      end

      def confirmed!(confirmed_at=DateTime.now)
        confirmation_token = nil
        confirmed_at       = confirmed_at # TODO: test optional arg.
      end

      def confirmation_token
        confirmation_token
      end

    private
      def compare_token(token)
        token == confirmation_token
      end
    end # Confirm
    include Confirm


    # we are using SHA512 so use this instead of Bcrypt

    require "digest/sha2"
    module Digest
      def digest
        return unless encrypted_password && password_salt
        digest = [password, salt].flatten.join('')
        stretches.times { digest = ::Digest::SHA512.hexdigest(digest) }
        digest
      end

      def digest!(password)
        # TODO convert to SHA512 when we are doing creation (right now only login)
        password_digest = BCrypt::Password.create(password)
      end

      def digest?(password)
        encrypted_password == sha_512_digest(password, 20, password_salt, nil)
      end

      def sha_512_digest(password, stretches = 20, salt, pepper)
        digest = [password, salt].flatten.join('')
        stretches.times { digest = ::Digest::SHA512.hexdigest(digest) }
        digest
      end
    end

    # require "bcrypt"
    # module Digest
    #   def digest
    #     return unless password_digest
    #     BCrypt::Password.new(password_digest)
    #   end
    #
    #   def digest!(password)
    #     password_digest = BCrypt::Password.create(password)
    #   end
    #
    #   def digest?(password)
    #     digest == password
    #   end
    # end
    include Digest

  end
end

defmodule RSA do
  @moduledoc """
  Module for work with rsa with des3 algorithm

  ## Examples

      iex> {private_key, public_key} = Rsa.generate_key(password)
      {private_key, public_key}

      iex> data = Rsa.encrypt_public(public_key, "test")
      <<152, 100, 17, 159, 201, 196, 169, 185, 200, 133, 48, 67, 139, 193, 89, 148,
        73, 58, 190, 9, 210, 129, 255, 83, 156, 246, 183, 187, 60, 194, 100, 154, 137,
        75, 66, 231, 8, 205, 166, 251, 215, 15, 218, 28, 127, 169, 28, 39, 118, 93,
        ...>>

      iex> Rsa.decrypt_private(private_key, data)
      "test"

  """

  @algorithm "des3"

  @doc """
  Generates public and private key with a `password`

  ## Parameters

    - password: Passphrase for rsa generation

  ## Examples

      iex> Rsa.generate_key(password)
      {private_key, public_key}

  """
  @spec generate_key(List.t) :: {List.t, List.t}
  def generate_key(password) do
    {pem, 0} = System.cmd "openssl", ["genrsa", "-#{@algorithm}", "-passout", "pass:#{password}"]
    {:RSAPrivateKey, :'two-prime', n, e, d, _p, _q, _e1, _e2, _c, _other} =
      pem
      |> :public_key.pem_decode
      |> List.first
      |> :public_key.pem_entry_decode(password)

    {[e, n, d], [e, n]}
  end


  @doc """
  Encryptes `data` with `public_key`

  ## Parameters

    - public_key: Public key, generated by `generate_key/1`
    - data: Data for encryption

  ## Examples

      iex> data = Rsa.encrypt_public(public_key, "test")
      <<152, 100, 17, 159, 201, 196, 169, 185, 200, 133, 48, 67, 139, 193, 89, 148,
        73, 58, 190, 9, 210, 129, 255, 83, 156, 246, 183, 187, 60, 194, 100, 154, 137,
        75, 66, 231, 8, 205, 166, 251, 215, 15, 218, 28, 127, 169, 28, 39, 118, 93,
        ...>>

  """
  @spec encrypt_public(List.t, String.t) :: BitString.t
  def encrypt_public(public_key, data) do
    :crypto.public_encrypt(:rsa, data, public_key, :rsa_pkcs1_padding)
  end

  @doc """
  Decryptes `data` with `private_key`

  ## Parameters

    - private_key: Private key, generated by `generate_key/1`
    - data: Data for decryption

  ## Examples

      iex> Rsa.decrypt_private(private_key, data)
      "test"

  """
  @spec decrypt_private(List.t, BitString.t) :: String.t
  def decrypt_private(private_key, data) do
    :crypto.private_decrypt(:rsa, data, private_key, :rsa_pkcs1_padding)
  end
end

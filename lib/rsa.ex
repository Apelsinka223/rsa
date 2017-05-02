defmodule Rsa do
  @moduledoc """
  Documentation for Rsa.
  """

  @doc """
  Hello world.

  ## Examples

      iex> Rsa.generate_key(password)
      {private_key, public_key}

      iex> Rsa.encrypt_public(public_key, "test")
      <<152, 100, 17, 159, 201, 196, 169, 185, 200, 133, 48, 67, 139, 193, 89, 148,
        73, 58, 190, 9, 210, 129, 255, 83, 156, 246, 183, 187, 60, 194, 100, 154, 137,
        75, 66, 231, 8, 205, 166, 251, 215, 15, 218, 28, 127, 169, 28, 39, 118, 93,
        ...>>

      iex> Rsa.decrypt_private(private_key, data)
      "test"
  """
  @doc """
    Generates public and private key with a password
  """
  @spec generate_key(String.t) :: {List.t, List.t}
  def generate_key(password) do
    {pem, 0} = System.cmd "openssl", ["genrsa", "-des3", "-passout", "pass:#{password}"]
    {:RSAPrivateKey, :'two-prime', n, e, d, _p, _q, _e1, _e2, _c, _other} = pem
      |> :public_key.pem_decode
      |> List.first
      |> :public_key.pem_entry_decode(password)
    private_key = [:crypto.mpint(e), :crypto.mpint(n), :crypto.mpint(d)]
    public_key = [:crypto.mpint(e), :crypto.mpint(n)]
    {private_key, public_key}
  end

  @doc """
    Encryptes data with public key
  """
  @spec encrypt_public(List.t, String.t) :: BitString.t
  def encrypt_public(public_key, data) do
    :crypto.rsa_public_encrypt(data, public_key, :rsa_pkcs1_padding)
  end

  @doc """
    Decryptes data with private key
  """
  @spec decrypt_private(List.t, BitString.t) :: String.t
  def decrypt_private(private_key, data) do
    :crypto.rsa_private_decrypt(data, private_key, :rsa_pkcs1_padding)
  end
end

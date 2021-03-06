%%%-------------------------------------------------------------------
%%% @author Mark <>
%%% @copyright (C) 2013, Mark
%%% @doc
%%%
%%% @end
%%% Created : 10 Nov 2013 by Mark <>
%%%-------------------------------------------------------------------
-module(sslv2decoder).

-export([decode/2,decode/1]).

-include("sslv2.hrl").

decode(Bin) ->
    parse_bin(Bin).

decode(Bin,DecryptInfo)->
    case decrypt(Bin,DecryptInfo) of
	{NewAesDecrypt,Plain} ->
	    {NewAesDecrypt, decode(Plain)};
	Plain ->
	    decode(Plain)
    end.


decrypt(Bin,#rsa_decrypt{private=Priv})->
    crypto:private_decrypt(rsa,Bin,Priv,rsa_pkcs1_padding);
decrypt(Bin,#aes_decrypt{state=State}) ->
    {NewState,PlainText} = crypto:stream_decrypt(State,Bin),
    {NewState,PlainText}.




parse_bin(<<?PROTOCOL_LABEL:16/big,
	    PacketType:8,
	    ContentLen:16/big,Rest/binary>>) 
  when size(Rest) == ContentLen ->
    parse_packet(PacketType,Rest);
parse_bin(<<?PROTOCOL_LABEL:16/big,
	    _PacketType:8,
	    ContentLen:16/big,Rest/binary>>) ->
    error_logger:info_msg("ContentLen: ~p but byte_size is: ~p ~n",
			  [ContentLen,byte_size(Rest)]),
    {error,{bad_len}};
parse_bin(Bin) ->
    {error,{unknown_bin,Bin}}.


parse_packet(?PT_CHANGE_KEY_SPEC,<<ModulusLen:16,Rest/binary>>)->
    ExpLen = size(Rest)-ModulusLen,
    <<Modulus:ModulusLen/bytes,PubExp:ExpLen/bytes>> = Rest,
    #change_keyspec{public_rsa = [binary_to_integer(Modulus),
				  binary_to_integer(PubExp)]};
parse_packet(?PT_CONN_REQUEST,<<Certificate/binary>>) ->
    #conn_request{cert=Certificate};
parse_packet(?PT_AUTH_PACKET,<<LoginLen:8,Rest/binary>>) ->
    <<Login:LoginLen/bytes,Password/bytes>>= Rest,
    #auth_packet{login = Login,password = Password};
parse_packet(?PT_DATA_TRANSFER,<<RecipientID:8,ContentType:8,Payload/binary>>) ->
    #data_transfer{recipient = RecipientID,
		   content_type = ContentType,
		   payload = Payload};
parse_packet(?PT_GET_ONLINE_USERS,<<>>) ->
    #get_online_users{};
parse_packet(?PT_AES_KEY,<<Key/binary>>) ->
    #aes_key{key=Key};
parse_packet(?PT_CLIENT_WANT_CHANGE_KEYSPEC,<<Reason:8>>)->
    #client_want_change_keyspec{reason = Reason};
parse_packet(Packet,Data) ->
    error({parse_packet,unknown_clause,[Packet,Data]}).


    

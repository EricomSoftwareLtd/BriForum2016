function getProtocol() {
        return window.location.protocol + "//";
    }

    function runURL() {
        var Url = GetBlazeFileURL($("#EUWS").val(), $("#Username").val(), $("#Password").val(), $("#application").val(), $("#group").val(), $("#param1").val(),
                                 $("#param2").val(),
                                 $("#encryptedPassword").is(':checked')
                    );
        if (Url != null) {
            window.open(getProtocol() + $("#EUWS").val() + "/EricomXML/AccessNow/start.html?autostart=true&settingsURL=" + Url, "dd");
        }
    }

   
    function runCookie() {
        var Url = GetBlazeFileURL($("#EUWS").val(), $("#Username").val(), $("#Password").val(), $("#application").val(), $("#group").val(), $("#param1").val(),
                                  $("#param2").val(),
                                  $("#encryptedPassword").is(':checked'));
        if (Url != null) {
            setCookie("EAN_settingsURL", Url, 1);
            window.open(getProtocol() + $("#EUWS").val() + "/EricomXML/AccessNow/start.html?autostart=true" + "&endURL=" + $("#endURL").val(), "_self");
        }
    }
    
    function runRedirect() {
        document.forms["test"].action = getProtocol() + $("#EUWS").val()  + "/EricomXML/AccessNowSso.aspx";
        $("#redirect").val("true");
        document.forms["test"].submit();
    }
    
    function setCookie(cname, cvalue, exdays) {
        var d = new Date();
        d.setTime(d.getTime() + (exdays*24*60*60*1000));
        var expires = "expires="+d.toGMTString();        
        document.cookie = cname + "=" + cvalue + "; " + expires + " ;path=/EricomXML/AccessNow/";
    }


    function GetBlazeFileURL(server, username, password, application, group, param1, param2, encrypted) {
        var ret;
        var values = [];

        $.ajax({
            type: "POST",
            url: getProtocol() + server + "/EricomXML/AccessNowSso.aspx",
            data: "Username=" + encodeURIComponent(username)
                   + "&password=" + encodeURIComponent(password)
                   + "&appName=" + encodeURIComponent(application)
                   + "&groupName=" + encodeURIComponent(group)
                   + "&param1=" + encodeURIComponent(param1)
                   + "&param2=" + encodeURIComponent(param2)
                   + "&encryptedPassword=" + encrypted,
            cache: false,
            async: false,
            success: function (data) {
                ret = data;
            },
            error: function (data, textStatus, jqXHR) {
                ret = null;
                alert("Error " + jqXHR);
            }
        });
        
        return ret;
    }

$(function() {
    $('form').each(function() {
        $(this).find('input').keypress(function(e) {
            // Enter pressed?
            if(e.which == 10 || e.which == 13) {
                runCookie();
            }
        });

        $(this).find('input[type=submit]').hide();
    });
});
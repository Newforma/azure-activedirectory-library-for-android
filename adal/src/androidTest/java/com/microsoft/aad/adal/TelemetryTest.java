// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package com.microsoft.aad.adal;

import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.content.pm.Signature;
import android.test.AndroidTestCase;
import android.test.suitebuilder.annotation.SmallTest;
import android.util.Base64;
import android.util.Log;
import android.util.Pair;

import org.mockito.Mockito;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

import static org.mockito.Mockito.when;

public class TelemetryTest extends AndroidTestCase {

    private static final String TAG = TelemetryTest.class.getSimpleName();

    @Override
    protected void setUp() throws Exception {
        super.setUp();
        Log.d(TAG, "setup key at settings");
        getContext().getCacheDir();
        System.setProperty("dexmaker.dexcache", getContext().getCacheDir().getPath());
    }

    @Override
    protected void tearDown() throws Exception {
        super.tearDown();
    }

    @SmallTest
    public void testAggregatedDispatcher() throws PackageManager.NameNotFoundException {
        final TestDispatcher dispatch = new TestDispatcher();
        final AggregatedDispatcher dispatcher = new AggregatedDispatcher(dispatch);
        final FileMockContext mockContext = createMockContext();

        final DefaultEvent default1 = new DefaultEvent();
        default1.setDefaults(mockContext, "client-id");
        default1.setEvent("a", "a");

        final DefaultEvent default2 = new DefaultEvent();

        dispatcher.receive("1", default1);
        dispatcher.receive("1", default2);

        dispatcher.flush("1");

        // We should not have any extra event over the default event
        assert(default1.getDefaultEventCount() >= dispatch.getEventCount());
    }

    @SmallTest
    public void testDefaultDispatcher() throws PackageManager.NameNotFoundException {
        final TestDispatcher dispatch = new TestDispatcher();
        final DefaultDispatcher dispatcher = new DefaultDispatcher(dispatch);
        final FileMockContext mockContext = createMockContext();

        final DefaultEvent default1 = new DefaultEvent();
        default1.setDefaults(mockContext, "client-id");
        default1.setEvent("a", "a");

        final DefaultEvent default2 = new DefaultEvent();

        dispatcher.receive("2", default1);
        assertEquals(default1.getEventList().size(), dispatch.getEventCount());

        dispatcher.receive("2", default2);
        assertEquals(default2.getEventList().size(), dispatch.getEventCount());
    }

    private PackageManager getMockedPackageManager() throws PackageManager.NameNotFoundException {
        final Signature mockedSignature = Mockito.mock(Signature.class);
        when(mockedSignature.toByteArray()).thenReturn(Base64.decode(
                Util.ENCODED_SIGNATURE, Base64.NO_WRAP));

        final PackageInfo mockedPackageInfo = Mockito.mock(PackageInfo.class);
        mockedPackageInfo.signatures = new Signature[] {mockedSignature};

        final PackageManager mockedPackageManager = Mockito.mock(PackageManager.class);
        when(mockedPackageManager.getPackageInfo(Mockito.anyString(), Mockito.anyInt())).thenReturn(mockedPackageInfo);

        // Mock intent query
        final List<ResolveInfo> activities = new ArrayList<>(1);
        activities.add(Mockito.mock(ResolveInfo.class));
        when(mockedPackageManager.queryIntentActivities(Mockito.any(Intent.class), Mockito.anyInt()))
                .thenReturn(activities);

        return mockedPackageManager;
    }

    private FileMockContext createMockContext()
            throws PackageManager.NameNotFoundException {

        final FileMockContext mockContext = new FileMockContext(getContext());

        final PackageManager mockedPackageManager = getMockedPackageManager();
        mockContext.setMockedPackageManager(mockedPackageManager);

        return mockContext;
    }

    class TestDispatcher implements IDispatcher {
        private int mEventCount = 0;

        public void dispatchEvent(List events) {
            mEventCount = events.size();
        }

        public int getEventCount() {
            return mEventCount;
        }
    }
}

class AggregatedTelemetryTestClass implements IDispatcher{

    private List<Pair<String, String>> eventData;

    AggregatedTelemetryTestClass() {
        eventData = new ArrayList<Pair<String, String>>();
    }

    @Override
    public void dispatchEvent(List<Pair<String, String>> events) {
        eventData.addAll(events);
    }

    boolean checkOauthError() {
        for (Pair<String, String> eventProperty : eventData) {
            if (eventProperty.first.equals(EventStrings.OAUTH_ERROR_CODE)) {
                return true;
            }
        }
        return false;
    }

    boolean checkNoPIIPresent(final String piiKey, final String piiValue) {

        // No event property should contain PII
        for (Pair<String, String> eventProperty : eventData) {
            if(eventProperty.second.equalsIgnoreCase(piiValue)) {
                return false;
            }
        }

        // Now check if we got the correct hash
        for (Pair<String, String> eventProperty : eventData) {
            if (eventProperty.first.equals(piiKey)) {
                try {
                    if (eventProperty.second.equals(StringExtensions.createHash(piiValue))) {
                        return true;
                    }
                } catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
                    return false;
                }
            }
        }
        return false;
    }

    boolean eventsReceived() {
        return (eventData.size() > 0);
    }
}

class DefaultTelemetryTestClass implements IDispatcher{

    private List<EventBlocks> eventData;

    DefaultTelemetryTestClass() {
        eventData = new ArrayList<EventBlocks>();
    }

    @Override
    public void dispatchEvent(List<Pair<String, String>> events) {
        eventData.add(new EventBlocks(events));
    }

    class EventBlocks {

        private List<Pair<String, String>> eventData;

        EventBlocks(List<Pair<String, String>> eventProperties) {
            eventData = eventProperties;
        }
    }

}
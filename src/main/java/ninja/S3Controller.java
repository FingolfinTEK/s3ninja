/*
 * Made with all the love in the world
 * by scireum in Remshalden, Germany
 *
 * Copyright by scireum GmbH
 * http://www.scireum.de - info@scireum.de
 */

package ninja;

import com.google.common.collect.Maps;
import com.google.common.hash.HashCode;
import com.google.common.hash.Hashing;
import com.google.common.io.BaseEncoding;
import com.google.common.io.ByteStreams;
import com.google.common.io.Files;
import io.netty.handler.codec.http.HttpHeaders;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpResponseStatus;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.time.ZoneOffset;
import java.time.chrono.IsoChronology;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.stream.Collectors;
import org.apache.commons.lang3.StringUtils;
import sirius.kernel.async.CallContext;
import sirius.kernel.commons.Strings;
import sirius.kernel.commons.Value;
import sirius.kernel.di.std.Part;
import sirius.kernel.di.std.Register;
import sirius.kernel.health.HandledException;
import sirius.kernel.xml.XMLStructuredOutput;
import sirius.web.controller.Controller;
import sirius.web.controller.Routed;
import sirius.web.http.Response;
import sirius.web.http.WebContext;

import static ninja.Aws4HashCalculator.AWS_AUTH4_PATTERN;
import static ninja.AwsHashCalculator.AWS_AUTH_PATTERN;

/**
 * Handles calls to the S3 API.
 *
 * @author Andreas Haufler (aha@scireum.de)
 * @since 2013/08
 */
@Register
public class S3Controller implements Controller {

    @Part
    private Storage storage;

    @Part
    private APILog log;

    @Part
    private AwsHashCalculator hashCalculator;

    @Override
    public void onError(WebContext ctx, HandledException error) {
        signalObjectError(ctx, HttpResponseStatus.BAD_REQUEST, error.getMessage());
    }

    /*
     * Computes the AWS Version 4 signing hash
     */

    /*
     * Extracts the given hash from the given request. Returns null if no hash was given.
     */
    private String getAuthHash(WebContext ctx) {
        Value authorizationHeaderValue = ctx.getHeaderValue(HttpHeaders.Names.AUTHORIZATION);
        if (!authorizationHeaderValue.isFilled()) {
            return ctx.get("Signature").getString();
        }
        String authentication = StringUtils.defaultString(authorizationHeaderValue.getString());
        Matcher m = AWS_AUTH_PATTERN.matcher(authentication);
        if (m.matches()) {
            return m.group(2);
        }

        m = AWS_AUTH4_PATTERN.matcher(authentication);
        if (m.matches()) {
            return m.group(5);
        }

        return null;
    }

    /*
     * Writes an API error to the log
     */
    private void signalObjectError(WebContext ctx, HttpResponseStatus status, String message) {
        ctx.respondWith().error(status, message);
        log.log("OBJECT " + ctx.getRequest().getMethod().name(),
            message + " - " + ctx.getRequestedURI(),
            APILog.Result.ERROR,
            CallContext.getCurrent().getWatch());
    }

    /*
     * Writes an API success entry to the log
     */
    private void signalObjectSuccess(WebContext ctx) {
        log.log("OBJECT " + ctx.getRequest().getMethod().name(),
            ctx.getRequestedURI(),
            APILog.Result.OK,
            CallContext.getCurrent().getWatch());
    }

    /**
     * Dispatching method handling all object specific calls.
     *
     * @param ctx        the context describing the current request
     * @param bucketName name of the bucket which contains the object (must exist)
     * @param idList     name of the object ob interest
     * @throws Exception in case of IO errors and there like
     */
    @Routed("/s3/:1/**")
    public void object(WebContext ctx, String bucketName, List<String> idList) throws Exception {
        Bucket bucket = storage.getBucket(bucketName);
        if (!bucket.exists()) {
            if (storage.isAutocreateBuckets()) {
                bucket.create();
            } else {
                signalObjectError(ctx, HttpResponseStatus.NOT_FOUND, "Bucket does not exist");
                return;
            }
        }

        if (requestUnauthorized(ctx, bucket)) {
            return;
        }

        String id = idList.stream().collect(Collectors.joining("/")).replace('/', '_');
        if (ctx.getRequest().getMethod() == HttpMethod.GET) {
            handleGetRequestFor(ctx, bucket, id);
        } else if (ctx.getRequest().getMethod() == HttpMethod.PUT) {
            Value copy = ctx.getHeaderValue("x-amz-copy-source");
            if (copy.isFilled()) {
                copyObject(ctx, bucket, id, copy.asString());
            } else {
                putObject(ctx, bucket, id);
            }
        } else if (ctx.getRequest().getMethod() == HttpMethod.DELETE) {
            handleDeleteRequest(ctx, bucket, id);
        } else if (ctx.getRequest().getMethod() == HttpMethod.HEAD) {
            getObject(ctx, bucket, id, false);
        } else {
            throw new IllegalArgumentException(ctx.getRequest().getMethod().name());
        }
    }

    private void handleGetRequestFor(final WebContext ctx, final Bucket bucket, final String id)
        throws Exception {
        if (StringUtils.isNotBlank(id)) {
            getObject(ctx, bucket, id, true);
        } else {
            listBucket(ctx, bucket);
        }
    }

    private boolean requestUnauthorized(final WebContext ctx, final Bucket bucket) {
        final String hash = getAuthHash(ctx);
        if (hash != null && isHashInvalid(ctx, hash)) {
            respondWithUnauthorizedMessage(ctx, "Invalid Hash " + hash);
            return true;
        }

        if (bucket.isPrivate() && !ctx.get("noAuth").isFilled() && hash == null) {
            respondWithUnauthorizedMessage(ctx, "Authentication required");
            return true;
        }
        return false;
    }

    private boolean isHashInvalid(final WebContext ctx, final String hash) {
        String expectedHash = computeHash(ctx, "");
        String alternativeHash = computeHash(ctx, "/s3");
        return !expectedHash.equals(hash) && !alternativeHash.equals(hash);
    }

    private String computeHash(WebContext ctx, String pathPrefix) {
        return hashCalculator.computeHash(ctx, pathPrefix);
    }

    private void respondWithUnauthorizedMessage(final WebContext ctx, final String message) {
        ctx.respondWith().error(HttpResponseStatus.UNAUTHORIZED, message);
        logRejectedRequest(ctx);
    }

    private void logRejectedRequest(final WebContext ctx) {
        log.log("OBJECT " + ctx.getRequest().getMethod().name(),
            ctx.getRequestedURI(),
            APILog.Result.REJECTED,
            CallContext.getCurrent().getWatch());
    }

    /**
     * Handles DELETE /bucket/id
     *
     * @param ctx    the context describing the current request
     * @param bucket the bucket containing the object to delete
     * @param id     name of the object to delete
     */

    private void handleDeleteRequest(WebContext ctx, Bucket bucket, String id) {
        if (StringUtils.isBlank(id)) {
            bucket.delete();
        } else {
            deleteObject(bucket, id);
        }

        ctx.respondWith().status(HttpResponseStatus.OK);
        signalObjectSuccess(ctx);
    }

    private void deleteObject(final Bucket bucket, final String id) {
        StoredObject object = bucket.getObject(id);
        object.delete();
    }

    /**
     * Handles PUT /bucket/id
     *
     * @param ctx    the context describing the current request
     * @param bucket the bucket containing the object to upload
     * @param id     name of the object to upload
     */
    private void putObject(WebContext ctx, Bucket bucket, String id) throws Exception {
        StoredObject object = bucket.getObject(id);
        InputStream inputStream = ctx.getContent();
        if (inputStream == null) {
            signalObjectError(ctx, HttpResponseStatus.BAD_REQUEST, "No content posted");
            return;
        }
        try {
            try (FileOutputStream out = new FileOutputStream(object.getFile())) {
                ByteStreams.copy(inputStream, out);
            }
        } finally {
            inputStream.close();
        }

        Map<String, String> properties = Maps.newTreeMap();
        for (String name : ctx.getRequest().headers().names()) {
            String nameLower = name.toLowerCase();
            if (nameLower.startsWith("x-amz-meta-") || nameLower.equals("content-md5") || nameLower
                .equals(
                    "content-type") || nameLower.equals("x-amz-acl")) {
                properties.put(name, ctx.getHeader(name));
            }
        }
        HashCode hash = Files.hash(object.getFile(), Hashing.md5());
        String md5 = BaseEncoding.base64().encode(hash.asBytes());
        if (properties.containsKey("Content-MD5")) {
            if (!md5.equals(properties.get("Content-MD5"))) {
                object.delete();
                signalObjectError(ctx,
                    HttpResponseStatus.BAD_REQUEST,
                    Strings.apply("Invalid MD5 checksum (Input: %s, Expected: %s)",
                        properties.get("Content-MD5"),
                        md5));
                return;
            }
        }

        object.storeProperties(properties);
        ctx.respondWith().addHeader(HttpHeaders.Names.ETAG, etag(hash))
            .status(HttpResponseStatus.OK);
        signalObjectSuccess(ctx);
    }

    private String etag(HashCode hash) {
        return "\"" + hash + "\"";
    }

    private DateTimeFormatter dateTimeFormatter =
        new DateTimeFormatterBuilder().appendPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").toFormatter()
            .withChronology(IsoChronology.INSTANCE).withZone(ZoneOffset.UTC);

    /**
     * Handles GET /bucket/id with an <tt>x-amz-copy-source</tt> header.
     *
     * @param ctx    the context describing the current request
     * @param bucket the bucket containing the object to use as destination
     * @param id     name of the object to use as destination
     */
    private void copyObject(WebContext ctx, Bucket bucket, String id, String copy)
        throws IOException {
        StoredObject object = bucket.getObject(id);
        /*
        if (!object.exists()) {
            signalObjectError(ctx, HttpResponseStatus.NOT_FOUND, "Object does not exist");
            return;
        }
        */
        if (!copy.contains("/")) {
            signalObjectError(ctx, HttpResponseStatus.BAD_REQUEST, "Source must contain '/'");
            return;
        }
        String srcBucketName = copy.substring(1, copy.lastIndexOf("/"));
        String srcId = copy.substring(copy.lastIndexOf("/") + 1);
        Bucket srcBucket = storage.getBucket(srcBucketName);
        if (!srcBucket.exists()) {
            signalObjectError(ctx, HttpResponseStatus.BAD_REQUEST, "Source bucket does not exist");
            return;
        }
        StoredObject src = srcBucket.getObject(srcId);
        if (!src.exists()) {
            signalObjectError(ctx, HttpResponseStatus.BAD_REQUEST, "Source object does not exist");
            return;
        }
        Files.copy(src.getFile(), object.getFile());
        if (src.getPropertiesFile().exists()) {
            Files.copy(src.getPropertiesFile(), object.getPropertiesFile());
        }
        HashCode hash = Files.hash(object.getFile(), Hashing.md5());
        String etag = etag(hash);
        XMLStructuredOutput structuredOutput =
            ctx.respondWith().addHeader(HttpHeaders.Names.ETAG, etag).xml();
        structuredOutput.beginOutput("CopyObjectResult");
        writeLastModifiedToXml(structuredOutput, object);
        structuredOutput.beginObject("ETag");
        structuredOutput.text(etag);
        structuredOutput.endObject();
        structuredOutput.endOutput();
        signalObjectSuccess(ctx);
    }

    private void writeLastModifiedToXml(
        final XMLStructuredOutput xmlStructuredOutput, final StoredObject object) {
        xmlStructuredOutput.beginObject("LastModified");
        xmlStructuredOutput.text(dateTimeFormatter.format(object.getLastModifiedInstant()));
        xmlStructuredOutput.endObject();
    }

    /**
     * Handles GET /bucket/id
     *
     * @param ctx    the context describing the current request
     * @param bucket the bucket containing the object to download
     * @param id     name of the object to use as download
     */
    private void getObject(WebContext ctx, Bucket bucket, String id, boolean sendFile)
        throws Exception {
        StoredObject object = bucket.getObject(id);
        if (!object.exists()) {
            signalObjectError(ctx, HttpResponseStatus.NOT_FOUND, "Object does not exist");
            return;
        }
        Response response = ctx.respondWith();
        for (Map.Entry<Object, Object> entry : object.getProperties()) {
            response.addHeader(entry.getKey().toString(), entry.getValue().toString());
        }
        if (sendFile) {
            response.file(object.getFile());
        } else {
            response.status(HttpResponseStatus.OK);
        }
        signalObjectSuccess(ctx);
    }

    private void listBucket(final WebContext ctx, final Bucket bucket) {
        List<StoredObject> objects = bucket.getObjects();
                                                                           
        Response response = ctx.respondWith();
        XMLStructuredOutput structuredOutput = response.xml();
        structuredOutput.beginOutput("ListBucketResult");
        writeBucketNameToXml(bucket, structuredOutput);
        objects.forEach(o -> writeObjectAsXml(structuredOutput, o));
        structuredOutput.endOutput();
        signalObjectSuccess(ctx);
    }

    private void writeBucketNameToXml(final Bucket bucket, final XMLStructuredOutput xmlOutput) {
        xmlOutput.beginObject("Name");
        xmlOutput.text(bucket.getName());
        xmlOutput.endObject();
    }

    private void writeObjectAsXml(final XMLStructuredOutput xmlOutput, final StoredObject object) {
        xmlOutput.beginObject("Contents");
        xmlOutput.beginObject("Key");
        xmlOutput.text(object.getName());
        xmlOutput.endObject();
        writeLastModifiedToXml(xmlOutput, object);
        xmlOutput.endObject();
    }
}

/*
 * Made with all the love in the world
 * by scireum in Remshalden, Germany
 *
 * Copyright by scireum GmbH
 * http://www.scireum.de - info@scireum.de
 */




import com.amazonaws.ClientConfiguration
import com.amazonaws.auth.AWSCredentials
import com.amazonaws.auth.BasicAWSCredentials
import com.amazonaws.services.s3.AmazonS3Client
import com.amazonaws.services.s3.S3ClientOptions
import com.amazonaws.services.s3.model.AmazonS3Exception
import com.amazonaws.services.s3.model.ObjectMetadata
import com.amazonaws.services.s3.model.S3Object
import com.google.common.base.Charsets
import com.google.common.io.ByteStreams
import sirius.kernel.BaseSpecification

class AWSSpec extends BaseSpecification {


    public static
    final ByteArrayInputStream TEST_DATA = new ByteArrayInputStream("Test".getBytes(Charsets.UTF_8))

    public AmazonS3Client getClient() {
        AWSCredentials credentials = new BasicAWSCredentials("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
        AmazonS3Client newClient = new AmazonS3Client(credentials,
                new ClientConfiguration());
        newClient.setS3ClientOptions(new S3ClientOptions().withPathStyleAccess(true));
        newClient.setEndpoint("http://localhost:9444/s3");

        return newClient;
    }

    def "PUT and then GET work as expected with AWS4 signer"() {
        given:
            def client = getClient();
        when:
            client.putObject("test", "test", TEST_DATA, new ObjectMetadata());

        def content = contentAsString(client.getObject("test", "test"));
        then:
            content == "Test"
    }

    private static String contentAsString(S3Object object) {
        new String(ByteStreams.toByteArray(object.getObjectContent()), Charsets.UTF_8)
    }

    def "PUT and then DELETE work as expected with AWS4 signer"() {
        given:
            def client = getClient();
        when:
            client.putObject("test", "test", TEST_DATA, new ObjectMetadata());
            client.deleteBucket("test");
            client.getObject("test", "test");
        then:
            AmazonS3Exception e = thrown();
            e.message == "Not Found (Service: Amazon S3; Status Code: 404; Error Code: 404 Not Found; Request ID: null)"
    }

    def "PUT and then List Bucket work as expected with AWS4 signer"() {
        given:
            def client = getClient();
        when:
            client.putObject("test", "test", TEST_DATA, new ObjectMetadata());
            def objects = client.listObjects("test").getObjectSummaries();
        then:
            objects.size() == 1
            objects[0].key == "test"
            
    }

}
